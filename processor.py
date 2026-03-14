"""
Core processing module for CISO Assistant Backup Generator.
Refactored from generate_applied_controls.py to work with in-memory file bytes.
"""

import zipfile
import xml.etree.ElementTree as ET
import json
import uuid
import random
import datetime
import gzip
import io


# Constants
TARGET_DATE = datetime.date.today()


def parse_xlsx(file_bytes, sheet_path='xl/worksheets/sheet1.xml'):
    """
    Parses an Excel file (.xlsx) from bytes using standard libraries.
    Returns a list of lists (rows).
    """
    try:
        with zipfile.ZipFile(io.BytesIO(file_bytes), 'r') as z:
            # Parse Shared Strings
            shared_strings = []
            if 'xl/sharedStrings.xml' in z.namelist():
                with z.open('xl/sharedStrings.xml') as f:
                    tree = ET.parse(f)
                    root = tree.getroot()
                    ns = {'main': 'http://schemas.openxmlformats.org/spreadsheetml/2006/main'}
                    for si in root.findall('main:si', ns):
                        t = si.find('main:t', ns)
                        if t is not None:
                            shared_strings.append(t.text)
                        else:
                            text = ""
                            for t_elem in si.findall('.//main:t', ns):
                                if t_elem.text:
                                    text += t_elem.text
                            shared_strings.append(text)

            # Parse Sheet
            rows = []
            if sheet_path in z.namelist():
                with z.open(sheet_path) as f:
                    tree = ET.parse(f)
                    root = tree.getroot()
                    ns = {'main': 'http://schemas.openxmlformats.org/spreadsheetml/2006/main'}
                    sheetData = root.find('main:sheetData', ns)
                    for row in sheetData.findall('main:row', ns):
                        row_data = []
                        columns = row.findall('main:c', ns)
                        for c in columns:
                            cell_type = c.get('t')
                            v = c.find('main:v', ns)
                            val = v.text if v is not None else ""
                            if cell_type == 's':  # shared string
                                if val.isdigit():
                                    val = shared_strings[int(val)]
                            row_data.append(val)
                        rows.append(row_data)
            return rows
    except Exception as e:
        raise ValueError(f"Error parsing xlsx: {e}")


def generate_random_timestamp(target_date):
    """
    Generates a random timestamp on the target_date.
    Format: YYYY-MM-DDTHH:MM:SS.mmmZ
    """
    start_time = datetime.datetime.combine(target_date, datetime.time.min)
    end_time = datetime.datetime.combine(target_date, datetime.time.max)
    delta = end_time - start_time
    random_seconds = random.randrange(int(delta.total_seconds()))
    random_time = start_time + datetime.timedelta(seconds=random_seconds)
    random_time = random_time.replace(microsecond=random.randint(0, 999999))
    return random_time.strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z'


def map_priority(val):
    if val == 'P1': return 1
    if val == 'P2': return 2
    if val == 'P3': return 3
    return 1


def map_effort(val):
    if val in ['Low', 'Medium', 'High']: return val[0]
    return 'M'


def map_impact(val):
    if val == 'High': return 4
    if val == 'Medium': return 3
    if val == 'Low': return 2
    return 4


def map_function(val):
    val = val.lower() if val else ""
    if 'identify' in val: return 'identify'
    if 'protect' in val: return 'protect'
    if 'detect' in val: return 'detect'
    if 'respond' in val: return 'respond'
    if 'recover' in val: return 'recover'
    if 'govern' in val: return 'govern'
    return 'identify'


def map_category(val):
    val = val.lower() if val else ""
    if 'technical' in val: return 'technical'
    if 'policy' in val: return 'policy'
    if 'organizational' in val: return 'organizational'
    return 'technical'


def find_folder_guid_by_name(data_list, folder_name):
    """
    Finds the pk of an iam.folder with the given name.
    """
    for item in data_list:
        if item.get('model') == 'iam.folder' and item.get('fields', {}).get('name') == folder_name:
            return item.get('pk')
    return None


def process_backup(applied_controls_bytes, vulnerabilities_bytes, source_backup_bytes):
    """
    Process uploaded files and return the merged backup as gzipped bytes.

    Args:
        applied_controls_bytes: Raw bytes of the applied controls .xlsx file
        vulnerabilities_bytes: Raw bytes of the vulnerabilities .xlsx file
        source_backup_bytes: Raw bytes of the source backup .bak file

    Returns:
        tuple: (output_bytes, stats_dict) where output_bytes is the gzipped backup
               and stats_dict contains processing statistics

    Raises:
        ValueError: If files cannot be parsed or backup structure is invalid
    """
    stats = {'applied_controls': 0, 'vulnerabilities': 0, 'total_items': 0}

    # 1. Load existing backup
    existing_data = None
    try:
        existing_data = json.loads(gzip.decompress(source_backup_bytes).decode('utf-8'))
    except (gzip.BadGzipFile, OSError):
        try:
            existing_data = json.loads(source_backup_bytes.decode('utf-8'))
        except Exception as e:
            raise ValueError(f"Could not parse backup file: {e}")

    # Check structure
    target_list = None
    if isinstance(existing_data, list) and len(existing_data) >= 2:
        if isinstance(existing_data[1], list):
            target_list = existing_data[1]

    if target_list is None:
        if isinstance(existing_data, list) and len(existing_data) > 0 and isinstance(existing_data[0], dict) and 'model' in existing_data[0]:
            target_list = existing_data
        else:
            raise ValueError("Unknown backup structure. Aborting to avoid corruption.")

    # Find Applied Control Folder GUID (Global)
    ac_folder_guid = find_folder_guid_by_name(target_list, 'Global')
    if not ac_folder_guid:
        raise ValueError("Could not find 'Global' folder in backup data.")

    # 2. Process Applied Controls
    level1_rows = parse_xlsx(applied_controls_bytes, 'xl/worksheets/sheet1.xml')
    level2_rows = parse_xlsx(applied_controls_bytes, 'xl/worksheets/sheet2.xml')

    all_ac_rows = []
    if level1_rows:
        all_ac_rows.extend(level1_rows[1:])
    if level2_rows:
        all_ac_rows.extend(level2_rows[1:])

    ac_count = 0
    for row in all_ac_rows:
        if not row:
            continue

        if len(row) < 8:
            row += [""] * (8 - len(row))

        control_id = row[0].strip()
        requirement = row[1].strip()
        config_setting = row[2].strip()
        category = row[3].strip()
        priority_val = row[4].strip()
        csf_function = row[5].strip()
        effort_val = row[6].strip()
        impact_val = row[7].strip()

        pk = str(uuid.uuid4())
        created_at = generate_random_timestamp(TARGET_DATE)
        updated_at = created_at

        name = f"{control_id}\t{requirement}"
        description = config_setting if config_setting else requirement

        item = {
            "model": "core.appliedcontrol",
            "pk": pk,
            "fields": {
                "created_at": created_at,
                "updated_at": updated_at,
                "name": name,
                "description": description,
                "folder": ac_folder_guid,
                "priority": map_priority(priority_val),
                "reference_control": None,
                "ref_id": control_id,
                "category": map_category(category),
                "csf_function": map_function(csf_function),
                "status": "--",
                "start_date": None,
                "eta": None,
                "expiry_date": None,
                "link": None,
                "effort": map_effort(effort_val),
                "control_impact": map_impact(impact_val),
                "cost": {
                    "currency": "€",
                    "amortization_period": 1,
                    "build": {"fixed_cost": 0, "people_days": 0},
                    "run": {"fixed_cost": 0, "people_days": 0}
                }
            }
        }
        target_list.append(item)
        ac_count += 1

    stats['applied_controls'] = ac_count

    # 3. Process Vulnerabilities
    vuln_folder_guid = ac_folder_guid
    vuln_rows = parse_xlsx(vulnerabilities_bytes)

    vuln_count = 0
    if vuln_rows:
        for row in vuln_rows[1:]:
            if not row:
                continue

            if len(row) < 4:
                row += [""] * (4 - len(row))

            ref_id = row[0].strip()
            name = row[1].strip()
            description = row[2].strip()

            pk = str(uuid.uuid4())
            created_at = generate_random_timestamp(TARGET_DATE)
            updated_at = created_at

            item = {
                "model": "core.vulnerability",
                "pk": pk,
                "fields": {
                    "created_at": created_at,
                    "updated_at": updated_at,
                    "name": name,
                    "description": description,
                    "folder": vuln_folder_guid,
                    "ref_id": ref_id,
                    "status": "potential",
                    "severity": 2,
                    "is_published": True,
                    "filtering_labels": [],
                    "applied_controls": [],
                    "assets": [],
                    "security_exceptions": []
                }
            }
            target_list.append(item)
            vuln_count += 1

    stats['vulnerabilities'] = vuln_count
    stats['total_items'] = len(target_list)

    # 4. Serialize to gzipped bytes
    json_bytes = json.dumps(existing_data, indent=None, separators=(',', ':')).encode('utf-8')
    output_bytes = gzip.compress(json_bytes)

    return output_bytes, stats
