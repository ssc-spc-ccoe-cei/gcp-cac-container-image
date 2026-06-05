#!/usr/local/bin/python
# -*- coding: latin-1 -*-

import json
import math
import os
import re
import sys

# Shared report colors
NON_COMPLIANT_TEXT_COLOR = "#721c24"
NON_COMPLIANT_BACKGROUND_COLOR = "#f8d7da"
NON_COMPLIANT_BORDER_COLOR = "#f5c6cb"

WARN_TEXT_COLOR = "#856404"
WARN_BACKGROUND_COLOR = "#fff3cd"
WARN_BORDER_COLOR = "#ffeeba"

PENDING_TEXT_COLOR = "#004085"
PENDING_BACKGROUND_COLOR = "#cce5ff"
PENDING_BORDER_COLOR = "#b8daff"

COMPLIANT_TEXT_COLOR = "#155724"
COMPLIANT_BACKGROUND_COLOR = "#d4edda"
COMPLIANT_BORDER_COLOR = "#c3e6cb"

INFO_TEXT_COLOR = "#0c5460"
INFO_BACKGROUND_COLOR = "#d1ecf1"
INFO_BORDER_COLOR = "#bee5eb"

DATA_MISSING_TEXT_COLOR = "#ffffff"
DATA_MISSING_BACKGROUND_COLOR = "#6f42c1"
DATA_MISSING_BORDER_COLOR = "#5a32a3"

NA_TEXT_COLOR = "#6c757d"
NA_BACKGROUND_COLOR = "#e9ecef"
NA_BORDER_COLOR = "#dee2e6"

BODY_BACKGROUND_COLOR = "#f4f6f8"
CONTAINER_BACKGROUND_COLOR = "#ffffff"
TEXT_COLOR = "#333333"
HEADING_COLOR = "#2c3e50"
MUTED_TEXT_COLOR = "#495057"
BORDER_LIGHT_COLOR = "#ecf0f1"
TABLE_BORDER_COLOR = "#dddddd"
TABLE_HEADER_BACKGROUND_COLOR = "#f8f9fa"
TABLE_HOVER_BACKGROUND_COLOR = "#f5f7fa"
SUMMARY_BACKGROUND_COLOR = "#e8f4f8"
SUMMARY_BORDER_COLOR = "#3498db"
FILTER_BORDER_COLOR = "#cbd5e1"
FILTER_BACKGROUND_COLOR = "#f8fafc"
FILTER_ACTIVE_COLOR = "#2563eb"
GROUP_HEADER_BACKGROUND_COLOR = "#e2e8f0"
PIE_TOTAL_BORDER_COLOR = "#dee2e6"

# Shared report CSS styles
REPORT_STYLES = f"""
body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; margin: 40px; background-color: {BODY_BACKGROUND_COLOR}; color: {TEXT_COLOR}; }}
.container {{ max-width: 1400px; margin: 0 auto; background-color: {CONTAINER_BACKGROUND_COLOR}; padding: 20px 40px; border-radius: 8px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); }}
h1 {{ color: {HEADING_COLOR}; border-bottom: 2px solid {BORDER_LIGHT_COLOR}; padding-bottom: 10px; }}
.summary {{ margin: 20px 0; padding: 15px; background-color: {SUMMARY_BACKGROUND_COLOR}; border-left: 4px solid {SUMMARY_BORDER_COLOR}; border-radius: 4px; }}
table {{ width: 100%; border-collapse: collapse; margin-top: 20px; }}
th, td {{ padding: 12px 15px; border-bottom: 1px solid {TABLE_BORDER_COLOR}; text-align: left; vertical-align: middle; }}
th {{ background-color: {TABLE_HEADER_BACKGROUND_COLOR}; font-weight: 600; color: {HEADING_COLOR}; }}
tr:hover {{ background-color: {TABLE_HOVER_BACKGROUND_COLOR}; }}
.status-badge {{ display: inline-block; padding: 6px 12px; border-radius: 12px; font-size: 0.85em; font-weight: bold; text-align: center; min-width: 80px; }}
.status-WARN {{ color: {WARN_TEXT_COLOR}; background-color: {WARN_BACKGROUND_COLOR}; border: 1px solid {WARN_BORDER_COLOR}; }}
.status-COMPLIANT {{ color: {COMPLIANT_TEXT_COLOR}; background-color: {COMPLIANT_BACKGROUND_COLOR}; border: 1px solid {COMPLIANT_BORDER_COLOR}; }}
.status-NON-COMPLIANT {{ color: {NON_COMPLIANT_TEXT_COLOR}; background-color: {NON_COMPLIANT_BACKGROUND_COLOR}; border: 1px solid {NON_COMPLIANT_BORDER_COLOR}; }}
.status-PENDING {{ color: {PENDING_TEXT_COLOR}; background-color: {PENDING_BACKGROUND_COLOR}; border: 1px solid {PENDING_BORDER_COLOR}; }}
.status-DATA-MISSING {{ color: {DATA_MISSING_TEXT_COLOR}; background-color: {DATA_MISSING_BACKGROUND_COLOR}; border: 1px solid {DATA_MISSING_BORDER_COLOR}; }}
.status-NON-APPLICABLE {{ color: {NA_TEXT_COLOR}; background-color: {NA_BACKGROUND_COLOR}; border: 1px solid {NA_BORDER_COLOR}; }}
.asset-name {{ word-break: break-all; font-family: monospace; font-size: 0.9em; color: {MUTED_TEXT_COLOR}; }}
.group-header {{ background-color: {GROUP_HEADER_BACKGROUND_COLOR}; font-weight: bold; color: {MUTED_TEXT_COLOR}; font-size: 1.1em; }}
.filter-label {{ font-weight: 600; color: {HEADING_COLOR}; margin-right: 8px; display: inline-block; }}
.filter-input {{ position: absolute; opacity: 0; pointer-events: none; }}
.filter-pill {{ border: 1px solid {FILTER_BORDER_COLOR}; padding: 6px 10px; border-radius: 999px; cursor: pointer; background: {FILTER_BACKGROUND_COLOR}; font-size: 0.9em; margin: 4px 6px 4px 0; display: inline-block; }}
.filter-input:checked + .filter-pill {{ background: {FILTER_ACTIVE_COLOR}; color: {CONTAINER_BACKGROUND_COLOR}; border-color: {FILTER_ACTIVE_COLOR}; }}
.filter-break {{ display: block; height: 0; margin-bottom: 12px; }}
.filter-dropdown {{ padding: 6px 12px; border: 1px solid {FILTER_BORDER_COLOR}; border-radius: 6px; background: {FILTER_BACKGROUND_COLOR}; font-size: 0.9em; color: {HEADING_COLOR}; cursor: pointer; min-width: 200px; }}
.filter-dropdown:focus {{ outline: none; border-color: {FILTER_ACTIVE_COLOR}; box-shadow: 0 0 0 2px rgba(37, 99, 235, 0.2); }}
.content-wrapper {{ display: flex; gap: 30px; align-items: flex-start; }}
.table-section {{ flex: 1; min-width: 0; }}
.pie-chart-container {{ flex-shrink: 0; width: 250px; text-align: center; background: {TABLE_HEADER_BACKGROUND_COLOR}; padding: 20px; border-radius: 8px; border: 1px solid {GROUP_HEADER_BACKGROUND_COLOR}; position: sticky; top: 20px; }}
.pie-chart-container h3 {{ margin: 0 0 15px 0; font-size: 1em; color: {HEADING_COLOR}; }}
.pie-chart {{ width: 180px; height: 180px; margin: 0 auto; }}
.pie-legend {{ margin-top: 15px; text-align: left; }}
.legend-item {{ display: flex; align-items: center; margin: 8px 0; font-size: 0.9em; }}
.legend-color {{ width: 16px; height: 16px; border-radius: 3px; margin-right: 8px; border: 2px solid; flex-shrink: 0; }}
.legend-label {{ color: {MUTED_TEXT_COLOR}; }}
.pie-total {{ margin-top: 15px; font-weight: 600; color: {HEADING_COLOR}; font-size: 0.9em; padding-top: 10px; border-top: 1px solid {PIE_TOTAL_BORDER_COLOR}; }}
.view-toggle {{ display: flex; justify-content: center; margin-bottom: 20px; gap: 10px; }}
.toggle-btn {{ padding: 8px 16px; cursor: pointer; border: 1px solid {FILTER_BORDER_COLOR}; background: {FILTER_BACKGROUND_COLOR}; border-radius: 6px; font-weight: bold; }}
.toggle-btn.active {{ background: {FILTER_ACTIVE_COLOR}; color: white; border-color: {FILTER_ACTIVE_COLOR}; }}
.view-section {{ display: none; }}
.view-section.active {{ display: block; }}
"""


#----------------------------------------
# HELPER FUNCTIONS
#----------------------------------------
def _generate_pie_chart(compliant, noncompliant, pending, missing):
    """Generate an SVG pie chart for guardrail compliance status."""
    total = compliant + noncompliant + pending + missing
    
    if total == 0:
        return ""

    # Colors matching the status badges
    colors = {
        "compliant": COMPLIANT_BACKGROUND_COLOR,
        "noncompliant": NON_COMPLIANT_BACKGROUND_COLOR,
        "pending": PENDING_BACKGROUND_COLOR,
        "missing": DATA_MISSING_BACKGROUND_COLOR,
    }
    border_colors = {
        "compliant": COMPLIANT_TEXT_COLOR,
        "noncompliant": NON_COMPLIANT_TEXT_COLOR,
        "pending": PENDING_TEXT_COLOR,
        "missing": DATA_MISSING_BORDER_COLOR,
    }

    segments = []
    if noncompliant > 0:
        segments.append(("Non-compliant", noncompliant, colors["noncompliant"], border_colors["noncompliant"]))
    if missing > 0:
        segments.append(("Data Missing", missing, colors["missing"], border_colors["missing"]))
    if pending > 0:
        segments.append(("Pending", pending, colors["pending"], border_colors["pending"]))
    if compliant > 0:
        segments.append(("Compliant", compliant, colors["compliant"], border_colors["compliant"]))

    # SVG parameters
    circle_x, circle_y, radius = 100, 100, 80
    paths = []
    current_angle = -90  # Start from top, 12 o'clock position

    for label, count, fill, stroke in segments:
        if count == 0:
            continue

        # Calculate percentage and angle for this segment/compliance count
        percentage = count / total
        angle = percentage * 360

        # Calculate arc
        start_angle_rad = math.radians(current_angle)
        end_angle_rad = math.radians(current_angle + angle)

        # Grab the start and end points for the arc
        x1 = circle_x + radius * math.cos(start_angle_rad)
        y1 = circle_y + radius * math.sin(start_angle_rad)
        x2 = circle_x + radius * math.cos(end_angle_rad)
        y2 = circle_y + radius * math.sin(end_angle_rad)

        large_arc = 1 if angle > 180 else 0

        if percentage == 1:
            # Full circle - need two arcs
            path = f'<circle cx="{circle_x}" cy="{circle_y}" r="{radius}" fill="{fill}" stroke="{stroke}" stroke-width="2"/>'
        else:
            path = f'<path d="M {circle_x},{circle_y} L {x1},{y1} A {radius},{radius} 0 {large_arc},1 {x2},{y2} Z" fill="{fill}" stroke="{stroke}" stroke-width="2"/>'

        paths.append(path)
        current_angle += angle

    # Build legend
    legend_items = []
    for label, count, fill, stroke in segments:
        percentage = round(count / total * 100)
        legend_items.append(
            f'<div class="legend-item">'
            f'<span class="legend-color" style="background:{fill};border-color:{stroke};"></span>'
            f'<span class="legend-label">{label}: {count} ({percentage}%)</span>'
            f'</div>'
        )

    # Build SVG pie chart
    svg = f'''
    <div class="pie-chart-container">
        <h3>Guardrail Compliance Overview</h3>
        <svg viewBox="0 0 200 200" class="pie-chart">
            {"".join(paths)}
        </svg>
        <div class="pie-legend">
            {"".join(legend_items)}
        </div>
        <div class="pie-total">Total Guardrails: {total}</div>
    </div>
    '''
    return svg


def _extract_project(asset_name):
    """Extract project ID from an asset name string.

    Args:
        asset_name: Asset name string (for example //.../projects/<project-id>/...)

    Returns:
        Project ID string, or None if not found
    """
    if not isinstance(asset_name, str):
        return None
    match = re.search(r"/projects/([^/]+)", asset_name)
    return match.group(1) if match else None


def _build_filters(guardrails, projects=None, include_warn=True, include_na=False, include_missing=True, view_prefix=""):
    """Build filter control markup for report pages.

    Args:
        guardrails: Ordered list of guardrail values
        projects: Optional ordered list of project IDs
        include_warn: Whether to include the warn status filter
        include_na: Whether to include the non-applicable status filter
        include_missing: Whether to include the data-missing status filter
        view_prefix: Prefix for element IDs to avoid collisions in unified report

    Returns:
        Filter controls HTML string
    """
    status_filters = [
        ("all", "All"),
        ("compliant", "Compliant"),
        ("noncompliant", "Non-compliant"),
        ("pending", "Pending"),
    ]

    # Only include warn status filter if requested. Only required for detailed reports
    if include_warn:
        status_filters.insert(2, ("warn", "Warn"))

    # Include data-missing filter for summary page only
    if include_missing:
        status_filters.append(("datamissing", "Missing"))

    # Include non-applicable filter for summary page when profile has recommended guardrails
    if include_na:
        status_filters.append(("nonapplicable", "Non-applicable"))

    prefix = f"{view_prefix}-" if view_prefix else ""

    controls = ['<div class="filter-controls">']
    controls.append('<span class="filter-label">Status Filter:</span>')
    for idx, (status_value, status_label) in enumerate(status_filters):
        checked = " checked" if idx == 0 else ""
        filter_id = f"{prefix}status-filter-{status_value}"
        controls.append(
            f'<input class="filter-input" type="radio" name="{prefix}status-filter" id="{filter_id}" value="{status_value}"{checked}>'
        )
        controls.append(f'<label class="filter-pill" for="{filter_id}">{status_label}</label>')
    controls.append('<div class="filter-break"></div>')

    controls.append('<span class="filter-label">Guardrail Filter:</span>')
    controls.append(f'<select id="{prefix}guardrail-filter" class="filter-dropdown">')
    controls.append('<option value="">All Guardrails</option>')
    for guardrail in guardrails:
        controls.append(f'<option value="{guardrail}">{guardrail}</option>')
    controls.append('</select>')
    controls.append('<div class="filter-break"></div>')

    if projects:
        controls.append('<span class="filter-label">Project Filter:</span>')
        controls.append(f'<select id="{prefix}project-filter" class="filter-dropdown">')
        controls.append('<option value="">All Projects</option>')
        for project in projects:
            controls.append(f'<option value="{project}">{project}</option>')
        controls.append('</select>')
        controls.append('<div class="filter-break"></div>')
    controls.append('</div>')

    return "\n".join(controls)


def _build_filter_script(view_prefix="", view_id=""):
    """Build a scoped filter script for a report view.

    Args:
        view_prefix: Prefix matching the filter control IDs
        view_id: DOM id of the view container to scope row queries

    Returns:
        JavaScript filter script HTML string
    """
    prefix = f"{view_prefix}-" if view_prefix else ""
    template = """
        <script>
            (function() {{
                var viewSection = document.getElementById("{view_id}");
                if (!viewSection) return;

                function applyFilters() {{
                    var selectedStatus = "all";
                    var checkedStatusInput = document.querySelector('input[name="{prefix}status-filter"]:checked');
                    if (checkedStatusInput) {{
                        selectedStatus = checkedStatusInput.value;
                    }}

                    var guardrailFilter = document.getElementById("{prefix}guardrail-filter");
                    var projectFilter = document.getElementById("{prefix}project-filter");
                    var selectedGuardrail = guardrailFilter ? guardrailFilter.value : "";
                    var selectedProject = projectFilter ? projectFilter.value : "";

                    var rows = viewSection.querySelectorAll("table tbody tr");
                    var visibleByGuardrail = {{}};

                    rows.forEach(function(row) {{
                        var rowType = row.dataset.rowType || "item";
                        if (rowType !== "item") {{
                            return;
                        }}

                        var rowStatus = row.dataset.statusGroup || "";
                        var rowGuardrail = row.dataset.guardrail || "";
                        var rowProject = row.dataset.project || "";

                        var statusMatches = selectedStatus === "all" || rowStatus === selectedStatus;
                        var guardrailMatches = !selectedGuardrail || rowGuardrail === selectedGuardrail;
                        var projectMatches = !selectedProject || rowProject === selectedProject;
                        var visible = statusMatches && guardrailMatches && projectMatches;

                        row.style.display = visible ? "" : "none";
                        if (visible) {{
                            visibleByGuardrail[rowGuardrail] = true;
                        }}
                    }});

                    rows.forEach(function(row) {{
                        if ((row.dataset.rowType || "") !== "group-header") {{
                            return;
                        }}
                        var headerGuardrail = row.dataset.guardrail || "";
                        row.style.display = visibleByGuardrail[headerGuardrail] ? "" : "none";
                    }});
                }}

                document.querySelectorAll('input[name="{prefix}status-filter"]').forEach(function(input) {{
                    input.addEventListener("change", applyFilters);
                }});

                var guardrailFilter = document.getElementById("{prefix}guardrail-filter");
                if (guardrailFilter) {{
                    guardrailFilter.addEventListener("change", applyFilters);
                }}

                var projectFilter = document.getElementById("{prefix}project-filter");
                if (projectFilter) {{
                    projectFilter.addEventListener("change", applyFilters);
                }}

                applyFilters();
            }})();
        </script>
    """
    return template.format(prefix=prefix, view_id=view_id)


#----------------------------------------
# REPORT GENERATION
#----------------------------------------
def generate_reports(data):
    """Generate a unified HTML report from JSON results.

    Args:
        data (list): A list of dictionaries containing the compliance results.

    Returns:
        str: The generated HTML report as a string.
    """

    # Load guardrail manifest
    manifest_path = os.path.join(os.path.dirname(__file__), 'guardrail_manifest.json')
    try:
        with open(manifest_path, 'r') as f:
            master_manifest = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError) as e:
        raise ValueError(f"Failed to load mandatory manifest at {manifest_path}: {e}. Ensure the file exists and is not empty.")

    # Extract profile level from data
    first = data[0] if data else {}
    profile_level = str(first.get("profile_level", "N/A"))

    # Build recommended guardrails set based on profile level
    recommended_guardrails = set()
    for guardrail_id, guardrail_data in master_manifest.items():
        if profile_level in guardrail_data.get("recommended_for_profiles", []):
            recommended_guardrails.add(guardrail_id)

    # Grab list of unique guardrails strictly from the manifest
    guardrails_list = sorted(master_manifest.keys())

    # Extract unique projects from asset names
    projects_set = set()
    for item in data:
        proj = _extract_project(item.get("asset_name", ""))
        if proj:
            projects_set.add(proj)
            
    projects_list = sorted(projects_set)

    # Build filters with prefixes so IDs are unique in the unified page
    summary_filters_html = _build_filters(guardrails_list, include_warn=False, include_na=bool(recommended_guardrails), include_missing=True, view_prefix="summary")
    detailed_filters_html = _build_filters(guardrails_list, projects_list, include_warn=True, include_na=False, include_missing=False, view_prefix="detailed")

    # ---------------------------------------------------------
    # SHARED HTML TEMPLATE
    # ---------------------------------------------------------
    html_template_start = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>{title}</title>
        <style>
            {report_styles}
        </style>
    </head>
    <body>
        <div class="container">
            <h1>{title}</h1>
    """

    # Grab the first item to extract summary data
    first = data[0] if data else {}

    # Add a summary block with extracted data
    summary_block = f"""
            <div class="summary">
                <strong>Organization:</strong> {first.get("organization", "N/A")} |
                <strong>App Version:</strong> {first.get("app_version", "N/A")} |
                <strong>Policy Version:</strong> {first.get("policy_version", "N/A")} |
                <strong>Date:</strong> {first.get("timestamp", "N/A")} |
                <strong>Profile Level:</strong> {profile_level}
            </div>
    """

    # ---------------------------------------------------------
    # TOGGLE UI
    # ---------------------------------------------------------
    toggle_html = """
        <div class="view-toggle">
            <button class="toggle-btn active" onclick="switchView('summary-view', this)">Summary</button>
            <button class="toggle-btn" onclick="switchView('detailed-view', this)">Details</button>
        </div>
    """

    toggle_script = """
        <script>
            function switchView(viewId, btn) {
                document.querySelectorAll('.view-section').forEach(el => el.classList.remove('active'));
                document.getElementById(viewId).classList.add('active');
                document.querySelectorAll('.toggle-btn').forEach(el => el.classList.remove('active'));
                btn.classList.add('active');
            }
        </script>
    """

    # ---------------------------------------------------------
    # DETAILED REPORT SECTION
    # ---------------------------------------------------------

    # Create a status order dictionary to sort items by status - whereby non-compliant items are first
    # Initialize summary_data from the Master Manifest
    summary_data = {}
    for guardrail, guardrail_data in master_manifest.items():
        validations = guardrail_data.get("validations", {})
        for validation, description in validations.items():
            key = (guardrail, validation)
            summary_data[key] = {
                "guardrail": guardrail,
                "validation": validation,
                "description": description,
                "statuses": {"DATA-MISSING"},
            }

    status_order = {
        "NON-COMPLIANT": 1,
        "DATA-MISSING": 2,
        "WARN": 3,
        "PENDING": 4,
        "COMPLIANT": 5,
    }

    detailed_data = sorted(
        data, key=lambda x: status_order.get(x.get("status", "UNKNOWN"), 5)
    )

    # Create the table headers for the detailed section
    detailed_section = f"""
    <div id="detailed-view" class="view-section">
        {detailed_filters_html}
        <table>
            <thead>
                <tr>
                    <th>Status</th>
                    <th>Guardrail</th>
                    <th>Validation</th>
                    <th>Description</th>
                    <th>Message</th>
                    <th>Asset Name</th>
                </tr>
            </thead>
            <tbody>
    """

    # Iterate through detailed data and build table rows
    for item in detailed_data:
        status = item.get("status", "UNKNOWN")
        status_group = str(status).lower().replace("-", "")
        guardrail = item.get("guardrail", "Unknown")
        project = _extract_project(item.get("asset_name", ""))
        
        detailed_section += f"""
                    <tr data-row-type="item" data-status-group="{status_group}" data-guardrail="{guardrail}" data-project="{project}">
                        <td><span class="status-badge status-{status}">{status}</span></td>
                        <td>{item.get("guardrail", "")}</td>
                        <td>{item.get("validation", "")}</td>
                        <td>{item.get("description", "")}</td>
                        <td>{item.get("msg", "")}</td>
                        <td class="asset-name">{item.get("asset_name", "")}</td>
                    </tr>
        """

    # Add table closing tags
    detailed_section += """
            </tbody>
        </table>
    </div>
    """

    # ---------------------------------------------------------
    # SUMMARY REPORT SECTION
    # ---------------------------------------------------------

    for item in data:
        guardrail = item.get("guardrail", "Unknown")
        validation = item.get("validation", "Unknown")
        description = item.get("description", "")
        status = item.get("status", "UNKNOWN")

        # Create a key that tracks the guardrail and validation
        key = (guardrail, validation)

        # If the key is not in summary data, then create it
        if key not in summary_data:
            # This handles findings that aren't in the manifest
            summary_data[key] = {
                "guardrail": guardrail,
                "validation": validation,
                "description": description,
                "statuses": {status},
            }
        else:
            # Replace DATA-MISSING if real data is found
            if "DATA-MISSING" in summary_data[key]["statuses"] and status != "UNKNOWN":
                summary_data[key]["statuses"].remove("DATA-MISSING")
            # Prefer description from results data if available
            if description:
                summary_data[key]["description"] = description

        # Tracks every discovered status across all items
        summary_data[key]["statuses"].add(status)

    # Iterate through the summary data and group validations under their respective guardrails
    guardrails = {}
    
    for key, value in summary_data.items():
        guardrail = value["guardrail"]
        if guardrail not in guardrails:
            guardrails[guardrail] = []
        guardrails[guardrail].append(value)

    # Calculate guardrail-level compliance for pie chart creation
    guardrail_compliant = 0
    guardrail_noncompliant = 0
    guardrail_pending = 0
    guardrail_missing = 0

    # Iterate through guardrails to calculate compliance status
    # If a validation is NON-COMPLIANT or PENDING, mark it accordingly - otherwise, it's compliant
    for guardrail, validations in guardrails.items():
        
        # Skip recommended guardrails - they don't count toward compliance totals
        if guardrail in recommended_guardrails:
            continue

        has_noncompliant = False
        has_pending = False
        has_missing = False

        for validation in validations:
            # DATA-MISSING is treated as a high-priority failure in the guardrail roll-up
            if "DATA-MISSING" in validation["statuses"]:
                has_missing = True
            # If any of the validation statuses are NON-COMPLIANT, then break out of the loop and mark the entire guardrail as non-compliant
            if "NON-COMPLIANT" in validation["statuses"]:
                has_noncompliant = True
                break
            # If any of the validation statuses are PENDING, then mark the entire guardrail as pending
            if "PENDING" in validation["statuses"]:
                has_pending = True
        if has_noncompliant:
            guardrail_noncompliant += 1
        elif has_missing:
            guardrail_missing += 1
        elif has_pending:
            guardrail_pending += 1
        else:
            guardrail_compliant += 1

    # Create the pie chart HTML
    pie_chart_html = _generate_pie_chart(guardrail_compliant, guardrail_noncompliant, guardrail_pending, guardrail_missing)

    summary_section = f"""
    <div id="summary-view" class="view-section active">
        {summary_filters_html}
        <div class="content-wrapper">
            <div class="table-section">
                <table>
                    <thead>
                        <tr>
                            <th style="width: 10%;">Guardrail</th>
                            <th style="width: 10%;">Validation</th>
                            <th>Description</th>
                            <th style="width: 15%; text-align: center;">Compliance Status</th>
                        </tr>
                    </thead>
                    <tbody>
    """

    # Create group headers for each guardrail
    for guardrail in sorted(guardrails.keys()):
        guardrail_name = master_manifest.get(guardrail, {}).get("name", "")
        header_text = f"Guardrail {guardrail} - {guardrail_name}" if guardrail_name else f"Guardrail {guardrail}"
        summary_section += f"""
                        <tr class="group-header" data-row-type="group-header" data-guardrail="{guardrail}">
                            <td colspan="4">{header_text}</td>
                        </tr>
        """

        # Sort by validation name within each guardrail
        validations = sorted(guardrails[guardrail], key=lambda x: x["validation"])

        for validation in validations:
            statuses = validation["statuses"]

            # For recommended guardrails, always show as NON-APPLICABLE on summary page
            if guardrail in recommended_guardrails:
                status = "Non-applicable"
            # Set the status appropriately based on if either NON-COMPLIANT or PENDING is in the statuses - fallback to compliant
            elif "NON-COMPLIANT" in statuses:
                status = "Non-compliant"
            elif "DATA-MISSING" in statuses:
                status = "Data-missing"
            elif "PENDING" in statuses:
                status = "Pending"
            else:
                status = "Compliant"

            # Set the status group for JavaScript filter
            status_group = str(status).lower().replace("-", "")

            summary_section += f"""
                        <tr data-row-type="item" data-status-group="{status_group}" data-guardrail="{guardrail}" data-project="">
                            <td><strong>{guardrail}</strong></td>
                            <td>{validation["validation"]}</td>
                            <td>{validation["description"]}</td>
                            <td style="text-align: center;"><span class="status-badge status-{status.upper()}">{status}</span></td>
                        </tr>
            """

    summary_section += f"""
                    </tbody>
                </table>
            </div>
            {pie_chart_html}
        </div>
    </div>
    """

    summary_filter_script = _build_filter_script(view_prefix="summary", view_id="summary-view")
    detailed_filter_script = _build_filter_script(view_prefix="detailed", view_id="detailed-view")

    # Combine all pieces of the HTML file into one
    combined_html = (
        html_template_start.replace("{title}", "Compliance Check - Report").replace("{report_styles}", REPORT_STYLES)
        + summary_block
        + toggle_html
        + summary_section
        + detailed_section
        + summary_filter_script
        + detailed_filter_script
        + toggle_script
        + "</div></body></html>"
    )

    return(combined_html)

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"Usage: python {sys.argv[0]} <path_to_results.ndjson>")
        sys.exit(1)

    input_path = sys.argv[1]
    output_path = os.path.splitext(input_path)[0] + ".html"

    try:
        with open(input_path, 'r', encoding='latin-1') as f:
            results_data = [json.loads(line) for line in f if line.strip()]

        html_report = generate_reports(results_data)

        with open(output_path, 'w') as f:
            f.write(html_report)

        print(f"Successfully generated HTML report: {output_path}")
    except Exception as e:
        print(f"Error during report generation: {e}")
        sys.exit(1)
