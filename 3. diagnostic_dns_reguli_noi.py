"""Diagnostic READ-ONLY pentru D/N/S propus, fără modificarea bazelor sau a dashboardului.

Rule-set candidat:
- D = maximul vecinilor DIRECTI de acelasi tip pentru orice nod din componenta.
- N = longest_path_capped existent, prag >=7.
- S = numarul entitatilor componentei, prag >=10.
- Alerta = OR (D>=5 or N>=7 or S>=10), doar pentru componente
  atinse de tranzactii active <=7 zile in ora analizata.
- Graf = ultimele 7 zile; tranzactii eligibile <=30 zile.
- UNREGISTERED: varsta maxima INDIVIDUALA a nodurilor ne-blacklistate,
  calculata din prima aparitie in istoricul local al TUTUROR diviziilor.
  Nu sunt folosite conexiuni nou-aparute pentru exceptii.

AVERTISMENT: 'first seen' local nu este first seen din Cynic.
Acest diagnostic nu inlocuieste inca motorul de productie si nu aplica verdictelor
politica de reactivare/expansiune din fraud_investigations.db.
"""
import argparse
import sqlite3
from collections import defaultdict
from datetime import datetime, timedelta
from pathlib import Path
from network_diagnostics_v2 import get_entities, load_blacklist, longest_path_capped
from network_ip_filter import network_ip_excluded

DIVS = ('MIP3IRELAND1', 'MIP3IRELAND2', 'MIP3IRELAND3')
UNREG = DIVS[2]


def age_ok(v, limit):
    """Valorile nule/incorecte raman eligibile, conform filtrului existent."""
    if v is None or isinstance(v, bool):
        return True
    try:
        days = float(str(v).strip())
        return not (days >= 0 and days > limit)
    except (TypeError, ValueError, OverflowError):
        return True


def same_type_direct(graph, component):
    return max((max((sum(1 for v in graph[u] if v[0] == kind)
                     for kind in ('EMAIL', 'CARD', 'PHONE')), default=0)
                for u in component), default=0)


def connected_components(graph, active):
    cache = {}
    out = {}
    for segment, nodes in active.items():
        touched = set()
        for node in nodes:
            if node not in cache:
                comp, stack = {node}, [node]
                while stack:
                    for nxt in graph[stack.pop()]:
                        if nxt not in comp:
                            comp.add(nxt)
                            stack.append(nxt)
                key = min(comp)
                for n in comp:
                    cache[n] = key
                out[key] = comp
            touched.add(cache[node])
        yield segment, touched, out


def main():
    parser = argparse.ArgumentParser(description='Read-only DNS diagnostic on latest date')
    parser.add_argument('--db', default='fraud_ireland.db')
    parser.add_argument('--blacklist', default='black list 3roi.csv')
    args = parser.parse_args()
    db = Path(args.db).resolve()
    bl = load_blacklist(Path(args.blacklist).resolve())
    conn = sqlite3.connect(db.as_uri() + '?mode=ro', uri=True)
    try:
        latest = conn.execute('SELECT MAX(tran_date) FROM transactions').fetchone()[0]
        if not latest:
            raise ValueError('Baza nu contine tranzactii')
        report_day = datetime.fromisoformat(latest).replace(hour=0,minute=0,second=0,microsecond=0)
        left = report_day - timedelta(days=7)
        first_seen = {}
        graph_rows = defaultdict(list)
        total = eligible30 = eligible7 = 0
        sql = '''SELECT tran_date,rrn,division_id,channel,payment_method,
                        cust_email,masked_card,home_msisdn,act_age,cust_ip
                 FROM transactions
                 WHERE division_id IN (?,?,?) AND tran_date <= ?
                 ORDER BY tran_date,rrn'''
        for stamp, rrn, div, channel, method, email, card, phone, acct_age, ip in conn.execute(sql, (*DIVS,latest)):
            total += 1
            at = datetime.fromisoformat(stamp)
            nodes = get_entities(email,card,phone,method,bl)
            # Historical first-seen includes all divisions, and is not limited to graph window.
            # Identify ages BEFORE registering this transaction.
            oldest_node_age = max(((at - first_seen.get(n,at)).total_seconds()/86400
                                   for n in nodes), default=0.0)
            for n in nodes:
                first_seen.setdefault(n, at)
            if at <= left or not nodes or network_ip_excluded(ip,bl):
                continue
            if div == UNREG:
                ok30 = oldest_node_age <= 30
                ok7 = oldest_node_age <= 7
            else:
                ok30 = age_ok(acct_age,30)
                ok7 = age_ok(acct_age,7)
            if not ok30:
                continue
            eligible30 += 1
            if ok7:
                eligible7 += 1
            seg=((channel or 'UNKNOWN').strip() or 'UNKNOWN',
                 (method or 'UNKNOWN').strip() or 'UNKNOWN')
            graph_rows[div].append((at, seg, nodes, ok7))
        print('READ ONLY | NEW RULES |',latest)
        print('Full history rows processed:',total,'| Graph 30d-eligible:',eligible30,
              '| Activation 7d-eligible:',eligible7)
        print('D >= 5 (same-type), N >= 7, S >= 10, OR')
        print('UNREGISTERED uses local first-seen of individual identifiers (no new-pair exception).')
        cutoff_latest = datetime.fromisoformat(latest)
        for div in DIVS:
            print('\nDIVISION:',div)
            rows=graph_rows[div]
            alert_count = 0
            seen_components = set()
            # Snapshot per hour; graph includes 7-day rolling history in each hour.
            for hour in range(cutoff_latest.hour + 1):
                begin=report_day + timedelta(hours=hour)
                cutoff=min(begin+timedelta(hours=1,seconds=-1),cutoff_latest)
                threshold=cutoff-timedelta(days=7)
                graph=defaultdict(set)
                active=defaultdict(set)
                for when,seg,nodes,is_active in rows:
                    if when>cutoff:
                        break
                    if when<=threshold:
                        continue
                    for node in nodes:
                        graph[node].update(nodes-{node})
                    if is_active and when>=begin:
                        active[seg].update(nodes)
                metrics_cache={}
                for seg,touched,components in connected_components(graph,active):
                    triggered=[]
                    for cid in touched:
                        if cid not in metrics_cache:
                            comp=components[cid]
                            d=same_type_direct(graph,comp)
                            n,n_status,_=longest_path_capped(graph,list(comp))
                            s=len(comp)
                            metrics_cache[cid]=(d,n,n_status,s)
                        d,n,n_status,s=metrics_cache[cid]
                        if d>=5 or n>=7 or s>=10:
                            triggered.append((cid,d,n,n_status,s))
                    if triggered:
                        alert_count+=1
                        for cid,d,n,n_status,s in triggered:
                            seen_components.add((hour,cid))
                            n_text=f'N{n}' if n_status=='exact' else f'N>={n}'
                            # No customer identifiers printed. Internal statistics only.
                            print(f'  {hour:02d}-{hour+1:02d} {seg[0]}/{seg[1]}: '
                                  f'D{d} {n_text} S{s}')
            print('Hourly segment alerts:',alert_count,
                  '| distinct hourly network occurrences:',len(seen_components))
    finally:
        conn.close()


if __name__=='__main__':
    main()
