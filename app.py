"""
Flask web application for CISO Assistant Backup Generator.
Accepts three file uploads and returns a merged downloadable .bak file.
"""

import datetime
from flask import Flask, render_template, request, send_file, flash, redirect, url_for
import io

from processor import process_backup

app = Flask(__name__)
app.secret_key = 'ciso-backup-generator-secret-key'
app.config['MAX_CONTENT_LENGTH'] = 200 * 1024 * 1024  # 200 MB max upload


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/generate', methods=['POST'])
def generate():
    # Validate all three files are present
    required_files = {
        'applied_controls': 'Applied Controls (.xlsx)',
        'vulnerabilities': 'Vulnerabilities (.xlsx)',
        'source_backup': 'Source Backup (.bak)',
    }

    for field, label in required_files.items():
        f = request.files.get(field)
        if not f or f.filename == '':
            flash(f'Missing required file: {label}', 'error')
            return redirect(url_for('index'))

    try:
        ac_bytes = request.files['applied_controls'].read()
        vuln_bytes = request.files['vulnerabilities'].read()
        backup_bytes = request.files['source_backup'].read()

        output_bytes, stats = process_backup(ac_bytes, vuln_bytes, backup_bytes)

        today = datetime.date.today().isoformat()
        filename = f'backup-{today}.bak'

        return send_file(
            io.BytesIO(output_bytes),
            mimetype='application/gzip',
            as_attachment=True,
            download_name=filename,
        )

    except ValueError as e:
        flash(f'Processing error: {e}', 'error')
        return redirect(url_for('index'))
    except Exception as e:
        flash(f'Unexpected error: {e}', 'error')
        return redirect(url_for('index'))


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
