"""3 Ireland: archive network alerts and expose Excel investigation views.

Reads fraud_ireland.db ONLY; writes fraud_investigations.db and FraudInvestigationData/*.csv.
Requires existing network_diagnostics_v2.py. Never changes Cynic transaction statuses.
Run manually first; add to scheduler only after validation.
"""
import argparse
import json
import csv
import hashlib
import os
import re
import sqlite3
import tempfile
import uuid
import time
import zipfile
from collections import defaultdict
from datetime import datetime, timedelta
from pathlib import Path
from xml.etree import ElementTree as ET

from network_diagnostics_v2 import get_entities, load_blacklist, longest_path_capped

ROOT = Path(__file__).resolve().parent
SOURCE = ROOT / 'fraud_ireland.db'
ARCHIVE = ROOT / 'fraud_investigations.db'
BLACKLIST = ROOT / 'black list 3roi.csv'
OUTPUT = ROOT / 'FraudInvestigationData'
EXCEL = ROOT / '3_Ireland_Fraud_Monitoring.xlsx'
DIVS = ('MIP3IRELAND1', 'MIP3IRELAND2', 'MIP3IRELAND3')
D_MIN, N_MIN, S_MIN = 5, 6, 10
SCHEMA = '''
CREATE TABLE IF NOT EXISTS cases (
 id TEXT PRIMARY KEY, division TEXT NOT NULL, status TEXT NOT NULL DEFAULT '',
 first_seen TEXT NOT NULL, last_seen TEXT NOT NULL, original_summary TEXT NOT NULL,
 active INTEGER NOT NULL DEFAULT 1, alert_reason TEXT NOT NULL,
 acknowledged_nodes TEXT NOT NULL DEFAULT '', acknowledged_edges TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS case_nodes (case_id TEXT, kind TEXT, value TEXT,
 first_seen TEXT NOT NULL, PRIMARY KEY(case_id,kind,value));
CREATE TABLE IF NOT EXISTS case_edges (case_id TEXT, a TEXT, b TEXT,
 first_seen TEXT NOT NULL, PRIMARY KEY(case_id,a,b));
CREATE TABLE IF NOT EXISTS case_rrns (case_id TEXT, rrn TEXT, first_seen TEXT NOT NULL,
 PRIMARY KEY(case_id,rrn));
CREATE TABLE IF NOT EXISTS case_events (
 id INTEGER PRIMARY KEY AUTOINCREMENT, case_id TEXT, detected_at TEXT,
 reason TEXT, details TEXT, UNIQUE(case_id,detected_at,reason,details));
CREATE TABLE IF NOT EXISTS verdict_log (
 id INTEGER PRIMARY KEY AUTOINCREMENT, case_id TEXT, old_verdict TEXT,
 new_verdict TEXT NOT NULL, recorded_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS confirmed_rrns (
 rrn TEXT PRIMARY KEY, source TEXT NOT NULL, confirmed_at TEXT NOT NULL,
 current_state TEXT NOT NULL DEFAULT 'CONFIRMED_FRAUD');
CREATE TABLE IF NOT EXISTS intake_items (
 fingerprint TEXT PRIMARY KEY, payload TEXT NOT NULL, processed_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS metadata (key TEXT PRIMARY KEY, value TEXT);
'''

def now():
    return datetime.now().strftime('%Y-%m-%d %H:%M:%S')

def nodekey(n):
    return n[0] + ':' + n[1]

def normalize_rrn(x):
    return str(x).strip().replace('\ufeff', '').replace('.0', '')

def initialize(c):
    c.executescript(SCHEMA)

def source_rows(c, start, end):
    columns = {r[1] for r in c.execute('PRAGMA table_info(transactions)')}
    mandatory = {'rrn','tran_date','division_id','channel','payment_method','cust_email','masked_card','home_msisdn'}
    missing = mandatory - columns
    if missing:
        raise ValueError('Missing source columns: ' + ', '.join(sorted(missing)))
    fields = ['rrn','tran_date','division_id','channel','payment_method','cust_email','masked_card','home_msisdn']
    for optional in ('fraud_status','total','currency','reversed','act_age'):
        fields.append(optional if optional in columns else f'NULL AS {optional}')
    sql = 'SELECT ' + ', '.join(fields) + ' FROM transactions WHERE tran_date > ? AND tran_date <= ? AND division_id IN (?,?,?) ORDER BY tran_date,rrn'
    out = []
    for raw in c.execute(sql, (start, end, *DIVS)):
        obj = dict(zip(('rrn','stamp','division','channel','method','email','card','phone','status','total','currency','reversed','age'), raw))
        out.append(obj)
    return out

def get_nodes(row, blacklist):
    return get_entities(row['email'],row['card'],row['phone'],row['method'],blacklist)

def graph_snapshot(rows, cutoff, hour_start, blacklist):
    threshold = cutoff - timedelta(days=7)
    graph, active, node_rrns = defaultdict(set), defaultdict(set), defaultdict(set)
    for r in rows:
        stamp = datetime.fromisoformat(r['stamp'])
        if stamp > cutoff: break
        if stamp <= threshold: continue
        nodes = get_nodes(r, blacklist)
        if not nodes: continue
        seg = ((r['channel'] or 'UNKNOWN').strip() or 'UNKNOWN', (r['method'] or 'UNKNOWN').strip() or 'UNKNOWN')
        for n in nodes:
            graph[n].update(nodes - {n})
            node_rrns[n].add(r['rrn'])
        if hour_start <= stamp <= cutoff:
            active[seg].update(nodes)
    return graph, active, node_rrns

def component_from(graph, start):
    seen, pending = {start}, [start]
    while pending:
        for other in graph[pending.pop()]:
            if other not in seen:
                seen.add(other); pending.append(other)
    return seen

def summarize(nodes, graph, rrns):
    counts = {k:sum(1 for x in nodes if x[0]==k) for k in ('PHONE','CARD','EMAIL')}
    leader = max(nodes, key=lambda n:(len(graph[n]),n))
    return (f"{len(nodes)} entitati: {counts['PHONE']} telefoane, {counts['CARD']} carduri, "
            f"{counts['EMAIL']} emailuri; {len(rrns)} RRN-uri; "
            f"nodul cu cele mai multe conexiuni este {leader[0]} ({len(graph[leader])} vecini directi).")

def persist_network(c, division, nodes, edges, rrns, summary, stamp, reason):
    keys = {nodekey(n) for n in nodes}
    candidates = []
    for case_id, verdict in c.execute('SELECT id,status FROM cases WHERE division=?',(division,)):
        known = {k+':'+v for k,v in c.execute('SELECT kind,value FROM case_nodes WHERE case_id=?',(case_id,))}
        shared = len(keys & known)
        if shared >= 2 and shared / min(len(keys),len(known)) >= 0.35:
            candidates.append((shared / len(keys | known), shared, case_id, verdict))
    candidates.sort(reverse=True)
    if len(candidates)>1 and candidates[1][1]>=2:
        # Joining previously separate cases: create a new case, never inherit verdict.
        candidates=[]
    if candidates:
        case_id, verdict = candidates[0][2:]
        existing_nodes = {k+':'+v for k,v in c.execute('SELECT kind,value FROM case_nodes WHERE case_id=?',(case_id,))}
        existing_edges = {tuple(x) for x in c.execute('SELECT a,b FROM case_edges WHERE case_id=?',(case_id,))}
        new_nodes = keys - existing_nodes
        new_edges = edges - existing_edges
        # Retrospective scans can revisit earlier hours: never move last_seen backwards.
        c.execute('UPDATE cases SET last_seen=CASE WHEN last_seen < ? THEN ? ELSE last_seen END WHERE id=?', (stamp,stamp,case_id))
        if new_nodes or new_edges:
            # Ordinary expansion of LEGITIMATE cases is archived but not escalated.
            if verdict != 'LEGITIMATE':
                c.execute('UPDATE cases SET active=1,alert_reason=? WHERE id=?', ('NETWORK EXPANSION', case_id))
                details = f'{len(new_nodes)} entitati noi, {len(new_edges)} legaturi noi'
                c.execute('INSERT OR IGNORE INTO case_events(case_id,detected_at,reason,details) VALUES (?,?,?,?)',
                          (case_id,stamp,'NETWORK EXPANSION',details))
    else:
        seq = c.execute("SELECT value FROM metadata WHERE key='case_seq'").fetchone()
        number = (int(seq[0]) if seq else 0)+1
        c.execute("INSERT OR REPLACE INTO metadata(key,value) VALUES('case_seq',?)",(str(number),))
        case_id=f'3ROI-{number:05d}'
        c.execute('INSERT INTO cases(id,division,first_seen,last_seen,original_summary,active,alert_reason) VALUES(?,?,?,?,?,1,?)',
                  (case_id,division,stamp,stamp,summary,reason))
        c.execute('INSERT OR IGNORE INTO case_events(case_id,detected_at,reason,details) VALUES (?,?,?,?)',
                  (case_id,stamp,reason,summary))
    for kind,val in nodes:
        c.execute('INSERT OR IGNORE INTO case_nodes VALUES(?,?,?,?)',(case_id,kind,val,stamp))
    for a,b in edges:
        c.execute('INSERT OR IGNORE INTO case_edges VALUES(?,?,?,?)',(case_id,a,b,stamp))
    for rrn in rrns:
        c.execute('INSERT OR IGNORE INTO case_rrns VALUES(?,?,?)',(case_id,rrn,stamp))
    return case_id

def detect(c, rows, blacklist, latest, days):
    latest_date=datetime.fromisoformat(latest).date()
    from_day=latest_date-timedelta(days=days-1)
    results=0
    for division in DIVS:
        divrows=[r for r in rows if r['division']==division]
        for dayidx in range(days):
            day=from_day+timedelta(days=dayidx)
            start=datetime.combine(day,datetime.min.time())
            for hour in range(24):
                hour_start=start+timedelta(hours=hour)
                if hour_start>datetime.fromisoformat(latest): break
                cutoff=min(hour_start+timedelta(hours=1,seconds=-1), datetime.fromisoformat(latest))
                graph,active,node_rrns=graph_snapshot(divrows, cutoff, hour_start, blacklist)
                if not active: continue
                components={}
                by_node={}
                for segment, segment_nodes in active.items():
                    touched=[]
                    for node in segment_nodes:
                        if node not in by_node:
                            comp=component_from(graph,node)
                            cid=min(comp)
                            for n in comp: by_node[n]=cid
                            d=max(len(graph[n]) for n in comp)
                            s=len(comp)
                            # Calculate N only for promising components to avoid excess DFS.
                            n, n_status, _ = longest_path_capped(graph,list(comp)) if s>=N_MIN else (0,'exact',0)
                            components[cid]=(comp,d,n,s,n_status)
                        touched.append(by_node[node])
                    touched=set(touched)
                    if not touched: continue
                    best_d=max(components[x][1] for x in touched)
                    best_n=max(components[x][2] for x in touched)
                    best_s=max(components[x][3] for x in touched)
                    # Dashboard may combine maxima from different components.
                    if best_d<D_MIN or best_n<N_MIN or best_s<S_MIN: continue
                    relevant=[x for x in touched if components[x][1]==best_d or components[x][2]==best_n or components[x][3]==best_s]
                    for cid in relevant:
                        comp,d,n,s,_=components[cid]
                        edge_set=set()
                        for node in comp:
                            for nei in graph[node]:
                                if nei in comp:
                                    edge_set.add(tuple(sorted((nodekey(node),nodekey(nei)))))
                        rrns=set().union(*(node_rrns[x] for x in comp))
                        summary=summarize(comp,graph,rrns)
                        reason='NETWORK ANOMALY' if d>=D_MIN and n>=N_MIN and s>=S_MIN else 'COMPOSITE NETWORK ALERT'
                        persist_network(c,division,comp,edge_set,rrns,summary,cutoff.strftime('%Y-%m-%d %H:%M:%S'),reason)
                        results+=1
    return results

# Read only fixed Excel user-entry cells; do not rewrite live Excel files.
# Analyst decisions: A4:B6, C4:D6, E4:F6 (9 slots).
# External fraud: H5:H54, one or multiple RRNs per cell; I5 source.
def read_excel_cells(path, sheet_title='Fraud Network Investigations'):
    ns={'x':'http://schemas.openxmlformats.org/spreadsheetml/2006/main',
        'r':'http://schemas.openxmlformats.org/officeDocument/2006/relationships',
        'p':'http://schemas.openxmlformats.org/package/2006/relationships'}
    with zipfile.ZipFile(path) as z:
        workbook=ET.fromstring(z.read('xl/workbook.xml'))
        target=None
        for s in workbook.findall('x:sheets/x:sheet',ns):
            if s.attrib['name']==sheet_title:
                target=s.attrib['{'+ns['r']+'}id'];break
        if target is None: raise ValueError('Foaia Fraud Network Investigations lipseste din Excel')
        rel=ET.fromstring(z.read('xl/_rels/workbook.xml.rels'))
        path_target=None
        for item in rel:
            if item.attrib['Id']==target: path_target=item.attrib['Target'];break
        if not path_target: raise ValueError('Excel worksheet relationship missing')
        path_target=path_target.lstrip('/')
        if not path_target.startswith('xl/'): path_target='xl/'+path_target
        strings=[]
        if 'xl/sharedStrings.xml' in z.namelist():
            strings=[''.join(t.text or '' for t in si.findall('.//x:t',ns)) for si in ET.fromstring(z.read('xl/sharedStrings.xml')).findall('x:si',ns)]
        root=ET.fromstring(z.read(path_target))
        out={}
        for cell in root.findall('.//x:sheetData/x:row/x:c',ns):
            ref=cell.attrib['r']; v=cell.find('x:v',ns)
            if cell.attrib.get('t')=='inlineStr':
                value=''.join(t.text or '' for t in cell.findall('.//x:t',ns))
            elif v is None: value=''
            elif cell.attrib.get('t')=='s': value=strings[int(v.text)]
            else: value=v.text or ''
            out[ref]=value
        return out

def import_inputs(c, excel):
    if not excel.is_file():
        print('Excel not found; decisions/confirmations skipped:',excel)
        return
    cells=read_excel_cells(excel)
    changes=0
    for left,right in [('A','B'),('C','D'),('E','F')]:
        for row in (4,5,6):
            case=(cells.get(f'{left}{row}') or '').strip().upper()
            verdict=(cells.get(f'{right}{row}') or '').strip().upper()
            if not case and not verdict:continue
            if not case or verdict not in ('FRAUDULENT','SUSPICIOUS','LEGITIMATE'):
                print('INVALID DECISION:',left,row,case,verdict);continue
            prev=c.execute('SELECT status FROM cases WHERE id=?',(case,)).fetchone()
            if prev is None:
                print('UNKNOWN CASE:',case);continue
            if prev[0]==verdict:continue
            c.execute('INSERT INTO verdict_log(case_id,old_verdict,new_verdict,recorded_at) VALUES(?,?,?,?)',
                      (case,prev[0],verdict,now()))
            baseline=json.dumps(sorted(k+':'+v for k,v in c.execute('SELECT kind,value FROM case_nodes WHERE case_id=?',(case,))))
            baseline_edges=json.dumps(sorted((a,b) for a,b in c.execute('SELECT a,b FROM case_edges WHERE case_id=?',(case,))))
            c.execute('UPDATE cases SET status=?, active=0, acknowledged_nodes=?, acknowledged_edges=? WHERE id=?',
                      (verdict,baseline,baseline_edges,case))
            changes+=1
    source=(cells.get('I5') or '').strip().upper()
    # Accept vertical paste across H5:H54 and also comma/newline separated values.
    pasted='\n'.join((cells.get(f'H{row}') or '') for row in range(5,55))
    if pasted.strip():
        if source not in ('CHARGEBACK','PAYPAL'):
            print('INVALID CONFIRMATION SOURCE; no RRN imported:',source)
        else:
            values=set()
            for raw in re.split(r'[\s,;]+',pasted):
                rrn=normalize_rrn(raw)
                if not rrn: continue
                if not re.fullmatch(r'[0-9]+',rrn):
                    print('INVALID RRN, skipped:',repr(rrn))
                    continue
                values.add(rrn)
            for rrn in sorted(values):
                exists=c.execute('SELECT source FROM confirmed_rrns WHERE rrn=?',(rrn,)).fetchone()
                if exists:
                    if exists[0]!=source: print('RRN already confirmed using source',exists[0],rrn)
                    continue
                c.execute('INSERT INTO confirmed_rrns(rrn,source,confirmed_at) VALUES(?,?,?)',(rrn,source,now()))
                changes+=1
            print('Confirmed fraud input: unique valid RRNs:', len(values))
    print('Changes imported from Excel:', changes)

def create_unlinked_confirmation_cases(c, row_by_rrn, blacklist):
    """A confirmed RRN not yet in any investigation should still surface as NEW."""
    for rrn, source, stamp in c.execute('SELECT rrn,source,confirmed_at FROM confirmed_rrns').fetchall():
        if c.execute('SELECT 1 FROM case_rrns WHERE rrn=? LIMIT 1',(rrn,)).fetchone():
            continue
        row=row_by_rrn.get(rrn)
        if not row:
            print('CONFIRMED RRN NOT FOUND in available source history:',rrn)
            continue
        nodes=get_nodes(row,blacklist)
        if not nodes:
            print('CONFIRMED RRN has no retained graph entities:',rrn)
            continue
        pairs={tuple(sorted((nodekey(a),nodekey(b)))) for a in nodes for b in nodes if a!=b}
        graph={n:nodes-{n} for n in nodes}
        summary=summarize(nodes,graph,{rrn})
        persist_network(c,row['division'],nodes,pairs,{rrn},summary,stamp,'CONFIRMED FRAUD LINK')

def apply_confirmations(c, row_by_rrn):
    """Only new external confirmations reopen suspicious/legitimate cases."""
    for rrn, source, stamp in c.execute('SELECT rrn,source,confirmed_at FROM confirmed_rrns').fetchall():
        if rrn not in row_by_rrn: continue
        row=row_by_rrn[rrn]
        direct_cases={x[0] for x in c.execute('SELECT case_id FROM case_rrns WHERE rrn=?',(rrn,)).fetchall()}
        # Cases connected by a shared retained entity also warrant review.
        for kind,val in get_nodes(row, load_blacklist(BLACKLIST)):
            direct_cases.update(x[0] for x in c.execute('SELECT case_id FROM case_nodes WHERE kind=? AND value=?',(kind,val)))
        for case in direct_cases:
            current=c.execute('SELECT status FROM cases WHERE id=?',(case,)).fetchone()[0]
            fingerprint=hashlib.sha256(f'{case}|{rrn}|{source}'.encode()).hexdigest()
            if c.execute('SELECT 1 FROM intake_items WHERE fingerprint=?',(fingerprint,)).fetchone(): continue
            c.execute('INSERT INTO intake_items VALUES (?,?,?)',(fingerprint,f'{case}|{rrn}|{source}',now()))
            if current in ('SUSPICIOUS','LEGITIMATE'):
                c.execute("UPDATE cases SET active=1,alert_reason='CONFIRMED FRAUD LINK' WHERE id=?",(case,))
                c.execute('INSERT OR IGNORE INTO case_events(case_id,detected_at,reason,details) VALUES(?,?,?,?)',
                          (case,stamp,'CONFIRMED FRAUD LINK',rrn))

def write_snapshot(prefix, records):
    """Create a complete, uniquely named CSV without replacing a Power Query source."""
    OUTPUT.mkdir(exist_ok=True, parents=True)
    stamp = datetime.now().strftime('%Y%m%d_%H%M%S_%f')
    dest = OUTPUT / f'{prefix}_{stamp}_{uuid.uuid4().hex[:8]}.csv'
    temp_path = None
    try:
        with tempfile.NamedTemporaryFile('w', newline='', encoding='utf-8-sig',
                                         dir=OUTPUT, suffix='.tmp', delete=False) as file:
            temp_path = Path(file.name)
            csv.writer(file).writerows(records)
        os.replace(temp_path, dest)  # New name, not an in-use Excel CSV.
        return dest
    finally:
        if temp_path is not None and temp_path.exists():
            temp_path.unlink()


def cleanup_snapshots(prefix, keep=3):
    """Only delete old snapshots of this exact feed; never touch legacy CSVs."""
    files = sorted(OUTPUT.glob(f'{prefix}_????????_??????_??????_????????.csv'),
                   key=lambda p: p.name, reverse=True)
    removed = 0
    for old in files[keep:]:
        try:
            old.unlink()
            removed += 1
        except (PermissionError, OSError) as exc:
            print(f'Cleanup skipped locked file {old.name}: {exc}')
    print(f'{prefix}: retained newest {min(len(files), keep)} snapshots; removed {removed}')


def export(c):
    active=[['Case ID','NEW / OLD','Row Type','Value','Details','Alert Reason']]
    hist=[['Case ID','Analyst Verdict','Row Type','Value','First Seen','Last Seen']]
    records=c.execute('SELECT id,division,status,first_seen,last_seen,original_summary,active,alert_reason FROM cases ORDER BY active DESC,last_seen DESC,id').fetchall()
    active_count=0
    confirmed={r[0] for r in c.execute("SELECT rrn FROM confirmed_rrns WHERE current_state='CONFIRMED_FRAUD'")}
    for case,division,verdict,first,last,summary,is_active,reason in records:
        nodes=c.execute('SELECT kind,value FROM case_nodes WHERE case_id=? ORDER BY kind,value',(case,)).fetchall()
        rrns=[r[0] for r in c.execute('SELECT rrn FROM case_rrns WHERE case_id=? ORDER BY first_seen DESC,rrn',(case,))]
        if is_active:
            active_count+=1
            status='NEW' if not verdict else 'OLD'
            baseline_row=c.execute('SELECT acknowledged_nodes FROM cases WHERE id=?',(case,)).fetchone()
            baseline=set(json.loads(baseline_row[0])) if baseline_row and baseline_row[0] else set()
            new_entity_nodes={kind+':'+val for kind,val in nodes}-baseline if status=='OLD' else set()
            describe=(f'{len(new_entity_nodes)} entitati noi. Descriere initiala: ' if status=='OLD' else '')+summary
            active.append([case,status,'CASE',division,describe,reason])
            # RRN list always separate from entity list.
            for rrn in sorted(rrns, key=lambda x:(x not in confirmed,x)):
                active.append([case,'','CONFIRMED RRN' if rrn in confirmed else 'RRN',rrn,'',''])
            for kind in ('PHONE','CARD','EMAIL'):
                for itemkind,value in sorted(nodes,key=lambda x:(x[0]+':'+x[1] not in new_entity_nodes,x[0],x[1])):
                    if itemkind==kind:active.append([case,'','NEW '+kind if kind+':'+value in new_entity_nodes else kind,value,'',''])
            active.append(['']*6)
        if verdict:
            hist.append([case,verdict,'CASE',division,first,last])
            for rrn in rrns: hist.append([case,'','CONFIRMED RRN' if rrn in confirmed else 'RRN',rrn,'',''])
            for kind,val in nodes: hist.append([case,'',kind,val,'',''])
            hist.append(['']*6)
    left_snapshot = write_snapshot('suspicious_activity', active)
    right_snapshot = write_snapshot('case_history', hist)
    print('Latest investigation CSVs:', left_snapshot.name, '|', right_snapshot.name)
    # Delete only older versioned snapshots. The legacy fixed-name CSVs remain
    # untouched until Power Query has been migrated and verified by the user.
    cleanup_snapshots('suspicious_activity', keep=3)
    cleanup_snapshots('case_history', keep=3)
    print('Exported active cases:',active_count,'archived cases:',sum(bool(r[2]) for r in records))

def main():
    p=argparse.ArgumentParser()
    p.add_argument('--days',type=int,default=3,help='Retrospective calendar days (default 3)')
    p.add_argument('--excel',type=Path,default=EXCEL)
    p.add_argument('--no-input',action='store_true',help='Skip reading analyst decisions until Excel is ready')
    args=p.parse_args()
    if not SOURCE.exists(): raise FileNotFoundError(SOURCE)
    blacklist=load_blacklist(BLACKLIST)
    src=sqlite3.connect(f'file:{SOURCE.as_posix()}?mode=ro',uri=True)
    latest=src.execute('SELECT MAX(tran_date) FROM transactions').fetchone()[0]
    if not latest: raise RuntimeError('Empty source')
    start=(datetime.fromisoformat(latest)-timedelta(days=args.days+7)).strftime('%Y-%m-%d %H:%M:%S')
    rows=source_rows(src,start,latest)
    row_by_rrn={r['rrn']:r for r in rows}
    dst=sqlite3.connect(ARCHIVE)
    initialize(dst)
    with dst:
        if not args.no_input:import_inputs(dst,args.excel)
        # A pending case is a work item, not a rolling-window result.
        # Keep it visible until an analyst submits a verdict, even if it
        # falls outside the 3-day detection window or 7-day graph window.
        pending_before={r[0] for r in dst.execute("SELECT id FROM cases WHERE status='' AND active=1")}
        detections=detect(dst,rows,blacklist,latest,args.days)
        missing_pending=pending_before-{r[0] for r in dst.execute("SELECT id FROM cases WHERE status='' AND active=1")}
        if missing_pending:
            raise RuntimeError('Pending cases disappeared without analyst decision: '+', '.join(sorted(missing_pending)))
        create_unlinked_confirmation_cases(dst,row_by_rrn,blacklist)
        apply_confirmations(dst,row_by_rrn)
        export(dst)
    print('Pending cases retained from before this scan:',len(pending_before))
    print('Latest Cynic:',latest,'| Source rows:',len(rows),'| qualifying detections:',detections)
    print('Investigation DB:',ARCHIVE,'| CSV folder:',OUTPUT)
    src.close();dst.close()

if __name__=='__main__':main()
