import argparse
import csv
import json
from concurrent.futures import ThreadPoolExecutor, as_completed
import folium
from ip_utils import lookup_ip

def read_ips(filepath):
    with open(filepath, "r") as f:
        return [line.strip() for line in f if line.strip()]

def write_to_csv(results, output_path):
    for r in results:
        lat = str(r.get("Lat", "")).strip()
        lon = str(r.get("Lon", "")).strip()
        if lat and lon:
            try:
                float(lat)
                float(lon)
                r["GoogleMapsURL"] = f"https://www.google.com/maps?q={lat},{lon}"
            except ValueError:
                r["GoogleMapsURL"] = ""
        else:
            r["GoogleMapsURL"] = ""

    all_keys = set()
    for r in results:
        all_keys.update(r.keys())

    keys = sorted(all_keys)
    with open(output_path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=keys)
        writer.writeheader()
        writer.writerows(results)

def write_to_json(results, output_path):
    with open(output_path, "w") as f:
        json.dump(results, f, indent=2)

def create_map(results, map_output_path):
    world_map = folium.Map(location=[20, 0], zoom_start=2)
    for item in results:
        try:
            lat = float(item["Lat"])
            lon = float(item["Lon"])
            tooltip = f"{item['IP']} - {item['City']}, {item['Country']}"
            folium.Marker(
                [lat, lon],
                popup=tooltip,
                icon=folium.Icon(color="red", icon="info-sign")
            ).add_to(world_map)
        except Exception:
            print(f"[!] Skipping IP {item.get('IP')} due to invalid coordinates.")
            continue
    world_map.save(map_output_path)

def main():
    parser = argparse.ArgumentParser(description="Bulk IP Geolocation Translator with Folium Map Support")
    parser.add_argument("-f", "--file", required=True, help="File with IPs (one per line)")
    parser.add_argument("-o", "--output", default="output/results.csv", help="Output CSV file path")
    parser.add_argument("--json", help="Output JSON file path")
    parser.add_argument("-t", "--threads", type=int, default=5, help="Number of parallel threads")
    parser.add_argument("--map", help="Output HTML map file path")
    args = parser.parse_args()

    ip_list = read_ips(args.file)
    results = []

    print(f"\n[*] Looking up {len(ip_list)} IPs using {args.threads} threads...\n")

    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        future_to_ip = {executor.submit(lookup_ip, ip): ip for ip in ip_list}
        for future in as_completed(future_to_ip):
            ip = future_to_ip[future]
            try:
                res = future.result()
                print(f"[✓] {ip}")
                results.append(res)
            except Exception as e:
                print(f"[!] Failed: {ip} - {e}")
                results.append({"IP": ip, "Country": "", "City": "", "Lat": "", "Lon": "", "ASN": "", "ReverseDNS": "", "Error": str(e)})

    # Write CSV output
    if results:
        write_to_csv(results, args.output)
        print(f"\n[✓] CSV saved to {args.output}")

    # Write JSON output if requested
    if args.json:
        write_to_json(results, args.json)
        print(f"[✓] JSON saved to {args.json}")

    # Create map if requested
    if args.map:
        create_map(results, args.map)
        print(f"[🗺️] Map saved to {args.map}")

if __name__ == "__main__":
    print(r"""
██████╗░██╗░░░██╗██╗░░░░░██╗░░██╗░░░░░░██╗██████╗░░░░░░░████████╗██████╗░░█████╗░███╗░░██╗░██████╗██╗░░░░░░█████╗░████████╗░█████╗░██████╗░
██╔══██╗██║░░░██║██║░░░░░██║░██╔╝░░░░░░██║██╔══██╗░░░░░░╚══██╔══╝██╔══██╗██╔══██╗████╗░██║██╔════╝██║░░░░░██╔══██╗╚══██╔══╝██╔══██╗██╔══██╗
██████╦╝██║░░░██║██║░░░░░█████═╝░█████╗██║██████╔╝█████╗░░░██║░░░██████╔╝███████║██╔██╗██║╚█████╗░██║░░░░░███████║░░░██║░░░██║░░██║██████╔╝
██╔══██╗██║░░░██║██║░░░░░██╔═██╗░╚════╝██║██╔═══╝░╚════╝░░░██║░░░██╔══██╗██╔══██║██║╚████║░╚═══██╗██║░░░░░██╔══██║░░░██║░░░██║░░██║██╔══██╗
██████╦╝╚██████╔╝███████╗██║░╚██╗░░░░░░██║██║░░░░░░░░░░░░░░██║░░░██║░░██║██║░░██║██║░╚███║██████╔╝███████╗██║░░██║░░░██║░░░╚█████╔╝██║░░██║
╚═════╝░░╚═════╝░╚══════╝╚═╝░░╚═╝░░░░░░╚═╝╚═╝░░░░░░░░░░░░░░╚═╝░░░╚═╝░░╚═╝╚═╝░░╚═╝╚═╝░░╚══╝╚═════╝░╚══════╝╚═╝░░╚═╝░░░╚═╝░░░░╚════╝░╚═╝░░╚═╝
                                                                                                              By-  DeViL PiKaChU""")
    main()
