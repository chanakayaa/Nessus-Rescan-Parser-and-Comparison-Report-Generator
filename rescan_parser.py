import xml.etree.ElementTree as ET
from collections import defaultdict
import os

def parse_nessus_file(file_path):
    vulnerabilities = defaultdict(lambda: {"Risk Factor": "None", "IP Addresses": set(), "Host State": set()})

    try:
        tree = ET.parse(file_path)
        root = tree.getroot()

        for report_host in root.findall(".//ReportHost"):
            host_ip = report_host.get("name")
            host_state = report_host.find(".//HostProperties/tag[@name='host-fqdn']").text.strip() if report_host.find(".//HostProperties/tag[@name='host-fqdn']") is not None else "Not Scanned"

            for item in report_host.findall(".//ReportItem"):
                risk_factor_element = item.find(".//risk_factor")
                if risk_factor_element is not None:
                    risk_factor = risk_factor_element.text.strip()
                else:
                    risk_factor = "None"

                if risk_factor != "None":
                    vulnerability_name = item.get("pluginName")
                    vulnerabilities[vulnerability_name]["Risk Factor"] = risk_factor
                    vulnerabilities[vulnerability_name]["IP Addresses"].add(host_ip)
                    vulnerabilities[vulnerability_name]["Host State"].add(host_state)

    except Exception as e:
        print("Error parsing Nessus file:", e)

    return vulnerabilities

def generate_html_report(initial_report, rescan_report, output_file):
    html_content = "<html><head><title>Nessus Comparison Report</title>"
    html_content += "<style>body { font-family: Verdana; } table {border-collapse: collapse; width: 100%;} th, td {padding: 8px; text-align: left; border: 1px solid #000000;}"
    html_content += "th {background-color: #1F497D; color: white; text-align: center; vertical-align: middle; border: 1px solid #000000;}"
    html_content += "tr:nth-child(even) {background-color: #ffffff;} tr:hover {background-color: #ddd;} .Critical {color: #C00000; text-align: center; font-weight: bold;}"
    html_content += ".High {color: #FF0000; text-align: center; font-weight: bold;} .Medium {color: #ED7D31; text-align: center; font-weight: bold;}"
    html_content += ".Low {color: #70AD47; text-align: center; font-weight: bold;} </style>"
    html_content += "<table><tr><th>Vulnerability</th><th>Criticality</th><th>Affected IPs </th><th>Not Fixed IPs</th></tr>"

    # Sort vulnerabilities by risk factor (Critical, High, Medium, Low)
    sorted_vulnerabilities = sorted(initial_report.items(), key=lambda x: ("Critical", "High", "Medium", "Low").index(x[1]["Risk Factor"]))

    # Iterate through sorted vulnerabilities
    for initial_vuln_name, initial_data in sorted_vulnerabilities:
        # Check if the vulnerability exists in the rescan report
        if initial_vuln_name in rescan_report:
            rescan_data = rescan_report[initial_vuln_name]

            # Generate HTML table row for the vulnerability
            html_content += "<tr>"
            html_content += f"<td style='border: 1px solid #000000;'><b>{initial_vuln_name}</b></td>"
            html_content += f"<td class='{initial_data['Risk Factor']}'>{initial_data['Risk Factor']}</td>"
            html_content += f"<td style='border: 1px solid #000000; text-align: center;'>{', '.join(initial_data['IP Addresses'])}</td>"
            html_content += f"<td style='border: 1px solid #000000; text-align: center;'>{', '.join(rescan_data['IP Addresses'])}</td>"
            html_content += "</tr>"
        else:
            # The vulnerability doesn't exist in the rescan report
            html_content += f"<tr><td style='border: 1px solid #000000;'><b>{initial_vuln_name}</b></td><td class='{initial_data['Risk Factor']}' style='border: 1px solid #000000; text-align: center;'>{initial_data['Risk Factor']}</td>"
            html_content += f"<td style='border: 1px solid #000000; text-align: center;'>{', '.join(initial_data['IP Addresses'])}</td><td style='border: 1px solid #000000;'></td></tr>"

    html_content += "</table></body></html>"

    with open(output_file, 'w', encoding='utf-8') as output:
        output.write(html_content)

if __name__ == "__main__":
    print("\n********************************************")
    print("*                                          *")
    print("*              NESSUS RESCAN PARSER        *")
    print("*                                          *")
    print("********************************************\n")

    initial_nessus_file = input("Enter the location of the initial Nessus file: ")
    rescan_nessus_file = input("Enter the location of the rescan Nessus file: ")

    if not os.path.isfile(initial_nessus_file) or not os.path.isfile(rescan_nessus_file):
        print("Error (404): FILE NOT FOUND")
    else:
        initial_report = parse_nessus_file(initial_nessus_file)
        rescan_report = parse_nessus_file(rescan_nessus_file)

        output_html_file = os.path.join(os.path.dirname(rescan_nessus_file), "rescan_table.html")

        generate_html_report(initial_report, rescan_report, output_html_file)

        print(f"GO CHECK YOUR FILE SYSTEM : {output_html_file}")



#------------------------------ CREATED BY PUSHKAR SINGH --------------------------------------------------------------------------------------------



# ------------------------------------------------------Scars On The Back Are A Swordsman's Shame ------------------------------------------------
