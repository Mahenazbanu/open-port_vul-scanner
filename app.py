from flask import Flask, render_template, request
from scanner_tool import port_scan, vulnerability_scan

app = Flask(__name__)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def scan():
    scan_type = request.form.get('scan_type')
    target = request.form.get('target')

    if scan_type == 'port_scan':
        port_range = request.form.get('port_range')
        if port_range:
            start_port, end_port = map(int, port_range.split('-'))
            result = port_scan(target, start_port, end_port)
        else:
            result = "Port range is required for port scan."
    elif scan_type == 'vulnerability_scan':
        result = vulnerability_scan(target)
    else:
        result = "Invalid scan type selected."

    return render_template('result.html', result=result)

if __name__ == "__main__":
    app.run(debug=True)