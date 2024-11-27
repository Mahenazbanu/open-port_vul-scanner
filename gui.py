from flask import Flask, render_template, request
from scanner_tool import port_scan, vulnerability_scan  # Assuming you have these functions in scanner_tool.py

# Initialize Flask app
app = Flask(__name__)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def scan():
    scan_type = request.form['scan_type']
    target = request.form['target']
    port_range = request.form.get('port_range', '')

    if scan_type == 'port':
        # Validate port range
        if not port_range or '-' not in port_range:
            return render_template('index.html', result="Error: Please provide a valid port range (e.g., 1-1000).")

        try:
            start_port, end_port = map(int, port_range.split('-'))
        except ValueError:
            return render_template('index.html', result="Error: Invalid port range format. Use 'start-end'.")
        
        # Call the port scan function
        result = port_scan(target, start_port, end_port)
    elif scan_type == 'vulnerability':
        # Call the vulnerability scan function
        result = vulnerability_scan(target)
    else:
        result = "Invalid scan type selected."

    return render_template('index.html', result=result)

if __name__ == '__main__':
    app.run(debug=True)
