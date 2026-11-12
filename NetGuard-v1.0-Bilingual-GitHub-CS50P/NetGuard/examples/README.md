# Example report behavior

Run `python project.py scan --host 127.0.0.1 --ports 22,80,443` to create
an actual report in the ignored `reports/` directory. Statuses vary with the
services running on your computer or Codespace.

The `compare` command accepts any two NetGuard JSON reports for the **same IP**.
It compares overlapping ports; ports that appear in only one report are listed
separately. No example is represented as a live security finding.
