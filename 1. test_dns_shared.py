"""Self-contained synthetic regression tests. Does not open real databases."""
from datetime import datetime, timedelta
from pathlib import Path
import sqlite3
import tempfile
import csv
from dns_common_engine import compute, load_or_build, metrics_for_day, valid_age

with tempfile.TemporaryDirectory() as tmp:
    root=Path(tmp)
    db=root/'synthetic.db'
    black=root/'black list 3roi.csv'
    with black.open('w',newline='',encoding='utf8') as f:
        w=csv.writer(f);w.writerow(['entity_type','entity_value','reason']);w.writerow(['email','generic@domain.test','generic']);w.writerow(['card_prefix','411111%','generic'])
    conn=sqlite3.connect(db)
    conn.execute('''CREATE TABLE transactions(tran_date TEXT,rrn TEXT, division_id TEXT,channel TEXT,
        payment_method TEXT,cust_email TEXT,masked_card TEXT,home_msisdn TEXT,act_age TEXT,cust_ip TEXT)''')
    dt=datetime(2026,11,11,10,10,0)
    def add(minutes,rrn,div,email,card,phone,age=0,channel='WEB',method='CARD'):
        conn.execute('INSERT INTO transactions VALUES(?,?,?,?,?,?,?,?,?,?)',
                     ((dt+timedelta(minutes=minutes)).strftime('%Y-%m-%d %H:%M:%S'),rrn,div,channel,method,email,card,phone,str(age),'127.0.0.1'))
    # five distinct phones connected to an EMAIL -> D5, S7 (5 phones+one email+shared card)
    for i in range(5):
        add(i,f'rrn{i}','MIP3IRELAND3','central@domain.test',f'550{i}xxxx',f'35385000000{i}')
    # Old historical identifier (35 days) + new phone: entire transaction excluded
    add(-36*24*60,'old','MIP3IRELAND1','legacy@domain.test','59999xxxx','353859999999',80)
    add(8,'newpair','MIP3IRELAND3','legacy@domain.test','59991xxxx','353851111111')
    # Old account in REGISTERED excluded from graph entirely
    add(11,'oldaccount','MIP3IRELAND2','other@domain.test','57777xxxx','353853333333',90)
    conn.commit()
    latest=conn.execute('SELECT MAX(tran_date) FROM transactions').fetchone()[0]
    bundle=compute(conn,latest,black,days=1)
    matched=[a for a in bundle['alerts'] if a['division']=='MIP3IRELAND3' and a['hour']==10]
    assert len(matched)==1,matched
    assert matched[0]['D']==5,matched
    assert matched[0]['S']==11,matched # 5 phone+5 cards+email
    assert 'newpair' not in matched[0]['rrns'],matched
    assert bundle['stats']['graph30']==5,bundle['stats']
    assert bundle['stats']['active7']==5,bundle['stats']
    assert valid_age(31,30)==False
    assert valid_age(None,30)==True
    # Candidate cache reused, not recalculated on same SQLite state
    x,status=load_or_build(conn,db,black,latest,days=1)
    y,status2=load_or_build(conn,db,black,latest,days=1)
    assert status=='CALCULAT' and status2=='CACHE',(status,status2)
    assert metrics_for_day(y,'MIP3IRELAND3','2026-11-11')[('WEB','CARD')][10][0]==5
    conn.close()
print('PASS: D same-type, 7/30 days, no new-pair exception, cache reuse, metric encoding')
