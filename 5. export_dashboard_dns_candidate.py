import csv
import os
import sqlite3
from datetime import date, timedelta, datetime, timezone
from pathlib import Path

from historical_averages import calculate_historical_averages
from network_hourly import combine_metrics, metrics_text
from dns_common_engine import load_or_build, metrics_for_day
from rolling_10min import analyze_division, episode_text
from data_coverage import read_coverage

PROJECT_DIR = Path(__file__).resolve().parent
DB_PATH = PROJECT_DIR / 'fraud_ireland.db'
DATA_DIR = PROJECT_DIR / 'DashboardData_DNS_Candidate'
BLACKLIST_PATH = PROJECT_DIR / 'black list 3roi.csv'

DIVISIONS = {
    'MIP3IRELAND1': 'REGISTRATION',
    'MIP3IRELAND2': 'REGISTERED',
    'MIP3IRELAND3': 'UNREGISTERED',
}


def format_comparison(actual, average):
    if actual is None:
        return ''
    if average is None:
        return f'{actual} / N/A'
    average_rounded = int(average + 0.5)
    alert = actual >= average * 2 and actual - average >= 30
    result = f'{actual} / {average_rounded}'
    if alert:
        result += ' !'
    return result


def save_csv(rows):
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S_%f')
    filename = f'dashboard_{stamp}.csv'
    final_path = DATA_DIR / filename
    temp_path = DATA_DIR / f'{filename}.tmp'
    try:
        with open(temp_path, 'w', newline='', encoding='utf-8-sig') as file:
            csv.writer(file).writerows(rows)
        os.rename(temp_path, final_path)
    finally:
        if temp_path.exists():
            temp_path.unlink()
    return final_path


def save_audit_csv(rows):
    """Non-PII per-minute historical interval audit; overwrite atomically."""
    folder = PROJECT_DIR / 'RollingData_DNS_Candidate'
    folder.mkdir(parents=True, exist_ok=True)
    destination = folder / 'rolling_10min_latest.csv'
    temp = folder / 'rolling_10min_latest.tmp'
    with open(temp, 'w', newline='', encoding='utf-8-sig') as file:
        out = csv.writer(file)
        out.writerow(['Division','Channel','Payment Method','Window Start',
                      'Actual 10m','History n','History Avg 10m',
                      'History Min 10m','History Max 10m',
                      'Provisional Threshold','Flagged'])
        out.writerows(rows)
    os.replace(temp, destination)


def main():
    if not DB_PATH.is_file():
        raise FileNotFoundError(f'Baza SQLite nu exista: {DB_PATH}')
    if not BLACKLIST_PATH.is_file():
        raise FileNotFoundError(f'Blacklistul lipseste: {BLACKLIST_PATH}')

    with sqlite3.connect(DB_PATH) as conn:
        latest = conn.execute('SELECT MAX(tran_date) FROM transactions').fetchone()[0]
        if not latest:
            raise RuntimeError('Nu exista tranzactii.')
        report_day = date.fromisoformat(latest[:10])
        report_str = report_day.isoformat()
        latest_time = latest[11:19]
        last_hour = int(latest_time[:2])
        previous_days = [report_day - timedelta(days=i) for i in range(1, 7)]
        header = (
            ['Channel', 'Payment Method']
            + [f'{h:02d} - {h + 1:02d}' for h in range(24)]
            + ['Total Day']
            + [day.strftime('%d.%m') for day in previous_days]
        )
        combined_rows = [header, ['REPORT DATE', report_str], ['LAST CYNIC', latest_time], []]
        grand_total = 0
        audit_rows = []
        bundle, cache_state = load_or_build(conn,DB_PATH,BLACKLIST_PATH,latest,days=3)
        print('DNS shared engine:', cache_state, '| alert components:',len(bundle['alerts']))
        print('Data raportului:', report_str)
        print('Ultima tranzactie Cynic:', latest)
        print('Istoric: pana la 28 de zile')
        print('Network: 7 zile, prag N>=10, doar Home MSISDN')

        for division_id, name in DIVISIONS.items():
            segments = conn.execute('''
                SELECT DISTINCT
                    COALESCE(NULLIF(channel, ''), 'UNKNOWN'),
                    COALESCE(NULLIF(payment_method, ''), 'UNKNOWN')
                FROM transactions WHERE division_id = ? ORDER BY 1, 2
            ''', (division_id,)).fetchall()

            averages = calculate_historical_averages(
                conn, division_id, report_str, latest_time, segments
            )
            # One call per division; all 24 hourly network snapshots computed.
            network_hours = metrics_for_day(bundle, division_id, report_str)

            rolling, rolling_stats, division_audit = analyze_division(
                conn, division_id, report_str, latest, segments
            )

            audit_rows.extend(division_audit)

            dashboard = {
                segment: [0 if h <= last_hour else None for h in range(24)]
                for segment in segments
            }
            hourly_rows = conn.execute('''
                SELECT
                    COALESCE(NULLIF(channel, ''), 'UNKNOWN'),
                    COALESCE(NULLIF(payment_method, ''), 'UNKNOWN'),
                    CAST(substr(hour_start, 12, 2) AS INTEGER),
                    SUM(transactions)
                FROM agg_hourly
                WHERE division_id = ? AND substr(hour_start, 1, 10) = ?
                GROUP BY 1, 2, 3
            ''', (division_id, report_str)).fetchall()

            for channel, method, hour, count in hourly_rows:
                key = (channel, method)
                if key not in dashboard:
                    raise RuntimeError(f'Segment necunoscut: {division_id}, {key}')
                dashboard[key][hour] = count

            historical_rows = conn.execute('''
                SELECT
                    tran_day,
                    COALESCE(NULLIF(channel, ''), 'UNKNOWN'),
                    COALESCE(NULLIF(payment_method, ''), 'UNKNOWN'),
                    SUM(transactions)
                FROM agg_daily
                WHERE division_id = ? AND tran_day >= ? AND tran_day < ?
                GROUP BY 1, 2, 3
            ''', (
                division_id, previous_days[-1].isoformat(), report_str
            )).fetchall()
            historical = {
                (day, channel, method): count
                for day, channel, method, count in historical_rows
            }
            # Daily totals are displayed whenever agg_daily has data for the day.
            # Coverage metadata is a freshness/completeness signal, not a reason
            # to hide existing daily transaction totals from the dashboard.
            available_days = {day for day, _channel, _method in historical}
            coverage_prev = read_coverage(
                conn, previous_days[-1].isoformat(), report_str
            )
            incomplete_days = sorted(
                day for day in available_days
                if coverage_prev.get(day, '') < day + ' 23:59:59'
            )
            if incomplete_days:
                print(f'{division_id}: totaluri istorice afisate, dar acoperire necertificata pentru:',
                      ', '.join(incomplete_days))

            division_rows = []
            actual_division_total = 0
            active_network_cells = 0
            for channel, method in segments:
                key = (channel, method)
                hours = dashboard[key]
                avg = averages[key]
                today_total = sum(value for value in hours if value is not None)
                actual_division_total += today_total
                metrics = network_hours.get(key, [None] * 24)

                hourly_display = []
                total_network = None
                for h in range(24):
                    comparison = format_comparison(hours[h], avg['hourly'][h])
                    metric = metrics[h]
                    if metric is not None and hours[h] is not None:
                        comparison += '\n' + metrics_text(metric)
                        total_network = combine_metrics(total_network, metric)
                        active_network_cells += 1
                    for episode in rolling[key].get(h, []):
                        comparison += "\n" + episode_text(episode)
                    hourly_display.append(comparison)

                total_display = format_comparison(today_total, avg['total_day'])
                if total_network is not None:
                    total_display += '\n' + metrics_text(total_network)

                previous_totals = []
                for day in previous_days:
                    day_str = day.isoformat()
                    previous_totals.append(
                        '' if day_str not in available_days else
                        historical.get((day_str, channel, method), 0)
                    )
                division_rows.append([
                    channel, method, *hourly_display,
                    total_display, *previous_totals
                ])

            expected = conn.execute('''
                SELECT COALESCE(SUM(transactions), 0) FROM agg_daily
                WHERE division_id = ? AND tran_day = ?
            ''', (division_id, report_str)).fetchone()[0]
            if actual_division_total != expected:
                raise RuntimeError(
                    f'Total incorect pentru {division_id}: '
                    f'{actual_division_total} fata de {expected}'
                )
            combined_rows.append([f'{division_id} - {name}'])
            combined_rows.extend(division_rows)
            combined_rows.extend([[], []])
            grand_total += actual_division_total
            days_used = averages[segments[0]]['days_used'] if segments else 0
            print(
                f'{division_id}: {actual_division_total} tranzactii, '
                f'{days_used} zile folosite la medie, '
                f'{active_network_cells} celule orare cu D/N/S; '
                f'{sum(v["episodes"] for v in rolling_stats.values())} episoade 10m'
            )

        expected_total = conn.execute('''
            SELECT COUNT(*) FROM transactions
            WHERE substr(tran_date, 1, 10) = ?
              AND division_id IN (?, ?, ?)
        ''', (report_str, *DIVISIONS.keys())).fetchone()[0]
        if grand_total != expected_total:
            raise RuntimeError(
                f'Total general incorect: {grand_total} fata de {expected_total}'
            )

    # NETWORK ALERT ENTITIES: same 33-column shape; only triggered components,
    # displayed in their original hourly column. Never show case IDs here.
    today_alerts = [a for a in bundle['alerts'] if a['day']==report_str]
    combined_rows.extend([[],[],['NETWORK ALERT ENTITIES']])
    for division_id, name in DIVISIONS.items():
        selected=[a for a in today_alerts if a['division']==division_id]
        if not selected: continue
        combined_rows.extend([[],[],[f'{division_id} - {name}']])
        by_segment={}
        for a in selected:
            by_segment.setdefault((a['channel'],a['method']),{}).setdefault(a['hour'],[]).append(a)
        for (channel,method), hours in sorted(by_segment.items()):
            max_rows=max(len(v) for v in hours.values())
            for index in range(max_rows):
                cells=['']*24
                for hour, items in sorted(hours.items()):
                    if index>=len(items):continue
                    entity=items[index]['entity']
                    cells[hour]=entity[1] if entity else '[NO PHONE/EMAIL]'
                combined_rows.append([channel, method, *cells, *(['']*7)])
    while combined_rows and not combined_rows[-1]:
        combined_rows.pop()
    path = save_csv(combined_rows)
    save_audit_csv(audit_rows)
    print('Total tranzactii astazi:', grand_total)
    print('Coloane CSV:', len(header))
    print('Fisier nou:', path.name)
    print('Export finalizat cu succes!')


if __name__ == '__main__':
    main()
