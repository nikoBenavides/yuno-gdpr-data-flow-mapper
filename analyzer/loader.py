import json
from pathlib import Path
from .models import Service, DataStore, ApiEndpoint, DataTransfer


def load_services(path: str) -> list[Service]:
    data = json.loads(Path(path).read_text())
    services = []
    for svc in data:
        services.append(Service(
            service_id=svc["service_id"],
            description=svc.get("description", ""),
            owner=svc.get("owner", "unknown"),
            region=svc["region"],
            data_stores=[
                DataStore(type=ds["type"], fields=ds["fields"])
                for ds in svc.get("data_stores", [])
            ],
            api_endpoints=[
                ApiEndpoint(
                    path=ep["path"],
                    request_fields=ep.get("request_fields", []),
                    response_fields=ep.get("response_fields", []),
                )
                for ep in svc.get("api_endpoints", [])
            ],
            retention_policy=svc.get("retention_policy"),
            lawful_basis=svc.get("lawful_basis"),
            data_transfers=[
                DataTransfer(
                    to_service=t["to_service"],
                    to_region=t["to_region"],
                    fields=t["fields"],
                    safeguard=t.get("safeguard"),
                )
                for t in svc.get("data_transfers", [])
            ],
        ))
    return services
