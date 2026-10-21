def detect_tech(web_services, config, output_file=None):
    print(f"[INF] Extracting technology stack from {len(web_services)} services")

    tech_stack = {}

    for service in web_services:
        techs = []
        if "[" in service and "]" in service:
            brackets = [s.strip("[]") for s in service.split() if s.startswith("[") and s != "[200]"]
            techs = [t for t in brackets if t]

        host = service.split()[0]
        if techs:
            tech_stack[host] = techs
            entry = f"[TECH] {host} {' '.join(techs)}"
            print(entry)
            if output_file:
                output_file.write(entry + "\n")

    print(f"[INF] Technology detection completed")
    return tech_stack
