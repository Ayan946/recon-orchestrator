from modules.utils import emit


def detect_tech(web_services, config, output_file=None):
    print(f"[INF] Extracting technology stack from {len(web_services)} services")

    tech_stack = {}

    for service in web_services:
        brackets = [s.strip("[]") for s in service.split() if s.startswith("[") and s.endswith("]")]
        techs = [b for b in brackets if not b.isdigit()]  # drop the status-code bracket

        host = service.split()[0]
        if techs:
            tech_stack[host] = techs
            emit(f"[TECH] {host} {' '.join(techs)}", output_file)

    print(f"[INF] Technology detection completed")
    return tech_stack
