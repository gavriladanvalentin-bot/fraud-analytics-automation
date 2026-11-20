import csv
import os
import sqlite3
from datetime import date, timedelta, datetime, timezone
from pathlib import Path

from historical_averages import calculate_historical_averages
from network_hourly import hourly_network_metrics, combine_metrics, metrics_text

PROJECT_DIR = Path(__file__).resolve().parent
DB_PATH = PROJECT_DIR / 'fraud_ireland.db'
DATA_DIR = PROJECT_DIR / 'DashboardData'
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
            network_hours = hourly_network_metrics(
                conn, division_id, report_str, latest, BLACKLIST_PATH
            )

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
            covered_days = {
                row[0] for row in conn.execute('''
                    SELECT DISTINCT tran_day FROM agg_daily
                    WHERE division_id = ? AND tran_day >= ? AND tran_day < ?
                ''', (
                    division_id, previous_days[-1].isoformat(), report_str
                ))
            }

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
                    hourly_display.append(comparison)

                total_display = format_comparison(today_total, avg['total_day'])
                if total_network is not None:
                    total_display += '\n' + metrics_text(total_network)

                previous_totals = []
                for day in previous_days:
                    day_str = day.isoformat()
                    previous_totals.append(
                        '' if day_str not in covered_days else
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
                f'{active_network_cells} celule orare cu D/N/S'
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

    while combined_rows and not combined_rows[-1]:
        combined_rows.pop()
    path = save_csv(combined_rows)
    print('Total tranzactii astazi:', grand_total)
    print('Coloane CSV:', len(header))
    print('Fisier nou:', path.name)
    print('Export finalizat cu succes!')


if __name__ == '__main__':
    main()
