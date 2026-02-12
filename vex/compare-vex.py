# Copyright (c) 2024 Vincent Danen
# License: GPLv3+

import argparse
import re
import requests
from collections import defaultdict
from rich.console import Console
from rich.table import Table

from .vex import Vex


def extract_product_names(vex_data):
    """
    Extract all product_name entries and their CPEs from a VEX file.
    
    Returns:
        dict: {product_id: set of CPEs}
    """
    product_names = defaultdict(set)
    
    def traverse_branches(branches):
        """Recursively traverse product_tree branches to find product_name entries."""
        if not branches:
            return
        
        for branch in branches:
            if branch.get('category') == 'product_name':
                product_id = None
                cpe = None
                
                # Check if product has product_id and product_identification_helper with CPE
                if 'product' in branch:
                    product = branch['product']
                    if 'product_id' in product:
                        product_id = product['product_id']
                    if 'product_identification_helper' in product:
                        helper = product['product_identification_helper']
                        if 'cpe' in helper:
                            cpe = helper['cpe']
                
                if product_id:
                    if cpe:
                        product_names[product_id].add(cpe)
                    else:
                        # Still add the entry even if no CPE
                        product_names[product_id].add(None)
            
            # Recursively traverse nested branches
            if 'branches' in branch:
                traverse_branches(branch['branches'])
    
    if 'product_tree' in vex_data and 'branches' in vex_data['product_tree']:
        traverse_branches(vex_data['product_tree']['branches'])
    
    return product_names


def extract_product_versions(vex_data):
    """
    Extract all product_version entries and their purls from a VEX file.
    
    Returns:
        dict: {product_id: set of purls}
    """
    product_versions = defaultdict(set)
    
    def traverse_branches(branches):
        """Recursively traverse product_tree branches to find product_version entries."""
        if not branches:
            return
        
        for branch in branches:
            if branch.get('category') in ('product_version', 'product_version_range'):
                product_id = None
                purl = None
                
                # Check if product has product_id and product_identification_helper with purl
                if 'product' in branch:
                    product = branch['product']
                    if 'product_id' in product:
                        product_id = product['product_id']
                    if 'product_identification_helper' in product:
                        helper = product['product_identification_helper']
                        if 'purl' in helper:
                            purl = helper['purl']
                
                if product_id:
                    if purl:
                        product_versions[product_id].add(purl)
                    else:
                        # Still add the entry even if no purl
                        product_versions[product_id].add(None)
            
            # Recursively traverse nested branches
            if 'branches' in branch:
                traverse_branches(branch['branches'])
    
    if 'product_tree' in vex_data and 'branches' in vex_data['product_tree']:
        traverse_branches(vex_data['product_tree']['branches'])
    
    return product_versions


def main():
    parser = argparse.ArgumentParser(
        description='Compare a VEX file with the corresponding Red Hat VEX file and show product_name entries (CPEs) and product_version entries (PURLs)'
    )
    parser.add_argument('vex_file', metavar='VEX_FILE', help='VEX file to compare')
    
    args = parser.parse_args()
    
    console = Console()
    
    # Load the first VEX file
    console.print(f'[cyan]Loading {args.vex_file}...[/cyan]')
    vex1 = Vex(args.vex_file)
    
    # Extract CVE ID from the VEX file
    cve_id = vex1.cve
    if not cve_id:
        console.print('[bold red]Error: Could not extract CVE ID from VEX file[/bold red]')
        return
    
    # Extract year from CVE ID (e.g., "CVE-2025-53014" -> "2025")
    cve_match = re.match(r'CVE-(\d{4})-\d+', cve_id)
    if not cve_match:
        console.print(f'[bold red]Error: Invalid CVE ID format: {cve_id}[/bold red]')
        return
    
    year = cve_match.group(1)
    
    # Construct download URL
    download_url = f'https://security.access.redhat.com/data/csaf/v2/vex/{year}/{cve_id.lower()}.json'
    
    # Download the second VEX file
    console.print(f'[cyan]Downloading {download_url}...[/cyan]')
    try:
        response = requests.get(download_url, timeout=10)
        response.raise_for_status()
        vex2 = Vex(response.json())
        console.print(f'[green]Successfully downloaded VEX file[/green]')
    except requests.exceptions.RequestException as e:
        console.print(f'[bold red]Error downloading VEX file: {e}[/bold red]')
        return
    
    # Extract product_name entries and CPEs
    product_names1 = extract_product_names(vex1.raw)
    product_names2 = extract_product_names(vex2.raw)
    
    # Extract product_version entries and purls
    product_versions1 = extract_product_versions(vex1.raw)
    product_versions2 = extract_product_versions(vex2.raw)
    
    # Set labels
    label1 = 'New VEX'
    label2 = 'Old VEX'
    
    # Create product_name comparison table
    console.print(f'\n[bold green]Product Name Entries and CPEs[/bold green]')
    table1 = Table(show_header=True, header_style="bold magenta")
    table1.add_column("Product ID", style="yellow", no_wrap=False)
    table1.add_column(f"CPE ({label2})", style="green", no_wrap=False)
    table1.add_column(f"CPE ({label1})", style="green", no_wrap=False)
    table1.add_column("Status", style="red", no_wrap=False)
    
    # Get all unique product IDs
    all_product_ids = set(product_names1.keys()) | set(product_names2.keys())
    
    for product_id in sorted(all_product_ids):
        cpes1 = product_names1.get(product_id, set())
        cpes2 = product_names2.get(product_id, set())
        
        # Determine status
        in_vex1 = product_id in product_names1
        in_vex2 = product_id in product_names2
        if in_vex1 and in_vex2:
            status = "Both"
        elif in_vex1:
            status = label1
        else:
            status = label2
        
        # Format CPEs (filter out None values)
        cpes1_list = sorted([c for c in cpes1 if c is not None])
        cpes2_list = sorted([c for c in cpes2 if c is not None])
        
        cpe1_str = ', '.join(cpes1_list) if cpes1_list else 'N/A'
        cpe2_str = ', '.join(cpes2_list) if cpes2_list else 'N/A'
        
        table1.add_row(product_id, cpe2_str, cpe1_str, status)
    
    console.print(table1)
    
    # Create product_version comparison table
    console.print(f'\n[bold green]Product Version Entries and PURLs[/bold green]')
    table2 = Table(show_header=True, header_style="bold magenta")
    table2.add_column("Product ID", style="cyan", no_wrap=False)
    table2.add_column(f"PURL ({label2})", style="green", no_wrap=False)
    table2.add_column(f"PURL ({label1})", style="green", no_wrap=False)
    table2.add_column("Status", style="red", no_wrap=False)
    
    # Get all unique product IDs
    all_product_ids = set(product_versions1.keys()) | set(product_versions2.keys())
    
    for product_id in sorted(all_product_ids):
        purls1 = product_versions1.get(product_id, set())
        purls2 = product_versions2.get(product_id, set())
        
        # Determine status
        in_vex1 = product_id in product_versions1
        in_vex2 = product_id in product_versions2
        if in_vex1 and in_vex2:
            status = "Both"
        elif in_vex1:
            status = label1
        else:
            status = label2
        
        # Format PURLs (filter out None values)
        purls1_list = sorted([p for p in purls1 if p is not None])
        purls2_list = sorted([p for p in purls2 if p is not None])
        
        purl1_str = ', '.join(purls1_list) if purls1_list else 'N/A'
        purl2_str = ', '.join(purls2_list) if purls2_list else 'N/A'
        
        table2.add_row(product_id, purl2_str, purl1_str, status)
    
    console.print(table2)


if __name__ == '__main__':
    main()
