 Nessus Rescan Parser and Comparison Report Generator

 Description

This Python script is designed to parse two Nessus XML files: an initial scan and a rescan. It compares the vulnerabilities found in both scans and generates an HTML report summarizing the vulnerabilities that were not fixed. The report includes details such as the vulnerability name, its criticality, and the affected IP addresses.

 Features

- Parses two Nessus XML files: initial scan and rescan.
- Extracts vulnerabilities and their criticalities, affected IP addresses, and host states.
- Compares the initial scan with the rescan to identify vulnerabilities that persist.
- Generates an HTML report summarizing the vulnerabilities and the affected IP addresses.

 Dependencies

- Python 3.x
- `xml.etree.ElementTree` (standard library)
- `collections.defaultdict` (standard library)
- `os` (standard library)

 Usage

 1. Prepare the Nessus XML Files

Ensure you have the initial and rescan Nessus XML files.

 2. Run the Script

Execute the script from the command line and provide the paths to your initial and rescan Nessus XML files when prompted.


python nessus_rescan_parser.py


 3. Enter the Nessus File Locations

When prompted, enter the full paths to your initial and rescan Nessus XML files.


Enter the location of the initial Nessus file: /path/to/your/initial_nessus_file.nessus
Enter the location of the rescan Nessus file: /path/to/your/rescan_nessus_file.nessus


 4. Check the Output

After successful execution, the script generates an HTML file named `rescan_table.html` in the same directory as your rescan Nessus XML file.


GO CHECK YOUR FILE SYSTEM : /path/to/your/rescan_table.html


 Sample Output

The generated HTML file will have a table format summarizing the vulnerabilities with their respective details, including which vulnerabilities persist in the rescan.



 Customization

Feel free to modify the script to fit your specific needs. You can adjust the HTML styles, add more details to the report, or integrate additional functionality as required.

 Credits

This script was created by Pushkar Singh. 

---

For any questions or issues, please contact the creator. Happy parsing!
