document.addEventListener("DOMContentLoaded", function () {
    const scanTypeSelect = document.getElementById('scan_type');
    const portRangeDiv = document.getElementById('port_range_div');

    // Show port range input only for port scan
    scanTypeSelect.addEventListener('change', function () {
        if (scanTypeSelect.value === 'port_scan') {
            portRangeDiv.style.display = 'block';  // Show the port range field
        } else {
            portRangeDiv.style.display = 'none';   // Hide the port range field
        }
    });

    // Trigger initial check in case the default option is already "port_scan"
    if (scanTypeSelect.value === 'port_scan') {
        portRangeDiv.style.display = 'block';
    }
});
