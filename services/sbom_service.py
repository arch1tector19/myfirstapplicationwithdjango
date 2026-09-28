import json
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import quote, urlparse
from uuid import uuid4

from services.url_service import is_archive_url


def get_github_repository(url: str) -> tuple[str, str] | None:
    parsed = urlparse(url)

    if parsed.netloc.lower() != "github.com":
        return None

    parts = [
        part
        for part in parsed.path.split("/")
        if part
    ]

    if len(parts) < 2:
        return None

    return parts[0], parts[1].removesuffix(".git")


def build_purl(component) -> str:
    current_purl = (component.purl or "").strip()

    if current_purl:
        return current_purl

    name = (component.component or "").strip()
    version = (component.version or "").strip()

    url = getattr(
        component,
        "external_reference_url",
        None,
    ) or ""

    host = urlparse(url).netloc.lower()

    github = get_github_repository(url)

    if github:
        owner, repository = github

        return (
            f"pkg:github/"
            f"{owner}/"
            f"{repository}"
            f"@{version}"
        )

    if "files.pythonhosted.org" in host:
        return (
            f"pkg:pypi/"
            f"{quote(name, safe='.-_~')}"
            f"@{version}"
        )

    if "registry.npmjs.org" in host:
        return (
            f"pkg:npm/"
            f"{quote(name, safe='@/.-_~')}"
            f"@{version}"
        )

    if "proxy.golang.org" in host:
        return (
            f"pkg:golang/"
            f"{quote(name, safe='/.-_~')}"
            f"@{version}"
        )

    if "maven.org" in host and ":" in name:
        group, artifact = name.split(":", 1)

        return (
            f"pkg:maven/"
            f"{quote(group, safe='.-_~')}/"
            f"{quote(artifact, safe='.-_~')}"
            f"@{version}"
        )

    if "nuget.org" in host:
        return (
            f"pkg:nuget/"
            f"{quote(name, safe='.-_~')}"
            f"@{version}"
        )

    return (
        f"pkg:generic/"
        f"{quote(name, safe='/.+-_~')}"
        f"@{version}"
    )


def build_external_references(component) -> list[dict]:
    url = getattr(
        component,
        "external_reference_url",
        None,
    ) or ""

    if not url:
        return []

    if is_archive_url(url):
        return [
            {
                "type": "distribution",
                "url": url,
            },
            {
                "type": "source-distribution",
                "url": url,
            },
        ]

    github = get_github_repository(url)

    if github:
        owner, repository = github

        return [
            {
                "type": "vcs",
                "url": (
                    f"https://github.com/"
                    f"{owner}/"
                    f"{repository}.git"
                ),
            }
        ]

    return [
        {
            "type": "distribution",
            "url": url,
        }
    ]


def build_properties(component) -> list[dict]:
    properties = [
        {
            "name": "GOST:attack_surface",
            "value": component.attack_surface or "",
        },
        {
            "name": "GOST:security_function",
            "value": component.security_function or "",
        },
    ]

    provided_by = (
        component.external_references or ""
    ).strip()

    external_url = getattr(
        component,
        "external_reference_url",
        None,
    )

    if provided_by and not external_url:
        properties.append(
            {
                "name": "GOST:provided_by",
                "value": provided_by,
            }
        )

    language = (
        component.lang or ""
    ).strip()

    if language:
        languages = [
            item.strip()
            for item in language.split(",")
            if item.strip()
        ]

        for language_name in languages:
            properties.append(
                {
                    "name": "GOST:source_langs",
                    "value": language_name,
                }
            )

    return properties


def build_sbom(components) -> dict:
    sbom_components = []
    dependencies = []

    for component in components:
        bom_ref = (
            component.bom_reference or ""
        ).strip()

        if not bom_ref:
            bom_ref = str(uuid4())

        component_data = {
            "type": component.type or "library",
            "bom-ref": bom_ref,
            "name": component.component or "",
            "version": component.version or "",
            "properties": build_properties(component),
        }

        external_references = (
            build_external_references(component)
        )

        if external_references:
            component_data[
                "externalReferences"
            ] = external_references

        component_data["purl"] = build_purl(
            component
        )

        sbom_components.append(
            component_data
        )

        dependencies.append(
            {
                "ref": bom_ref,
                "dependsOn": [],
            }
        )

    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": (
            f"urn:uuid:{uuid4()}"
        ),
        "version": 3,
        "metadata": {
            "timestamp": (
                datetime.now(timezone.utc)
                .strftime(
                    "%Y-%m-%dT%H:%M:%SZ"
                )
            ),
            "tools": [
                {
                    "vendor": "OWASP",
                    "name": "Dependency-Track",
                    "version": "4.12.0",
                }
            ],
            "component": {
                "type": "application",
                "bom-ref": str(uuid4()),
                "name": "RT Protect EDR",
                "version": "4.0.0",
                "manufacturer": {
                    "name": (
                        "АО "
                        "«РТ-Информационная безопасность»"
                    )
                },
            },
        },
        "components": sbom_components,
        "dependencies": dependencies,
    }


def generate_sbom_json(components) -> str:
    return json.dumps(
        build_sbom(components),
        ensure_ascii=False,
        indent=2,
    )


# ---------------------------------------------------------------------
# СРАВНЕНИЕ SBOM
# ---------------------------------------------------------------------


def compare_sbom(
    generated: dict,
    reference: dict,
) -> dict:
    """
    Сравнивает сформированный SBOM с эталонным SBOM.

    Динамические поля:
    - serialNumber
    - bom-ref
    - metadata.timestamp

    не считаются ошибками, поскольку они создаются заново
    при каждой генерации SBOM.
    """

    result = {
        "success": True,
        "top_level": {},
        "metadata": {},
        "components": {},
        "field_differences": {},
        "purl": {},
        "external_references": {},
        "dependencies": {},
    }

    # -------------------------------------------------------------
    # Верхнеуровневые поля
    # -------------------------------------------------------------

    for field in (
        "bomFormat",
        "specVersion",
        "version",
    ):
        result["top_level"][field] = {
            "reference": reference.get(field),
            "generated": generated.get(field),
            "matches": (
                reference.get(field)
                == generated.get(field)
            ),
        }

    # -------------------------------------------------------------
    # Metadata
    # -------------------------------------------------------------

    reference_metadata = reference.get(
        "metadata",
        {},
    )

    generated_metadata = generated.get(
        "metadata",
        {},
    )

    result["metadata"]["tools"] = {
        "reference": reference_metadata.get("tools"),
        "generated": generated_metadata.get("tools"),
        "matches": (
            reference_metadata.get("tools")
            == generated_metadata.get("tools")
        ),
    }

    reference_component = (
        reference_metadata.get(
            "component",
            {},
        )
    )

    generated_component = (
        generated_metadata.get(
            "component",
            {},
        )
    )

    metadata_component_differences = {}

    for field in (
        "type",
        "name",
        "version",
        "manufacturer",
    ):
        reference_value = reference_component.get(field)
        generated_value = generated_component.get(field)

        if reference_value != generated_value:
            metadata_component_differences[field] = {
                "reference": reference_value,
                "generated": generated_value,
            }

    result["metadata"][
        "component_differences"
    ] = metadata_component_differences

    # -------------------------------------------------------------
    # Компоненты
    # -------------------------------------------------------------

    reference_components = reference.get(
        "components",
        [],
    )

    generated_components = generated.get(
        "components",
        [],
    )

    result["components"]["reference_count"] = (
        len(reference_components)
    )

    result["components"]["generated_count"] = (
        len(generated_components)
    )

    result["components"]["count_matches"] = (
        len(reference_components)
        == len(generated_components)
    )

    def build_component_map(components):
        component_map = {}

        for component in components:
            key = (
                component.get("name", ""),
                component.get("version", ""),
            )

            component_map.setdefault(
                key,
                [],
            ).append(component)

        return component_map

    reference_map = build_component_map(
        reference_components
    )

    generated_map = build_component_map(
        generated_components
    )

    reference_keys = set(reference_map)
    generated_keys = set(generated_map)

    only_reference = (
        reference_keys - generated_keys
    )

    only_generated = (
        generated_keys - reference_keys
    )

    result["components"][
        "only_in_reference"
    ] = sorted(
        [
            {
                "name": key[0],
                "version": key[1],
            }
            for key in only_reference
        ],
        key=lambda item: (
            item["name"],
            item["version"],
        ),
    )

    result["components"][
        "only_in_generated"
    ] = sorted(
        [
            {
                "name": key[0],
                "version": key[1],
            }
            for key in only_generated
        ],
        key=lambda item: (
            item["name"],
            item["version"],
        ),
    )

    # -------------------------------------------------------------
    # Сравнение полей компонентов
    # -------------------------------------------------------------

    ignored_component_fields = {
        "bom-ref",
    }

    field_difference_counts = {}

    for key in reference_keys & generated_keys:
        reference_items = reference_map[key]
        generated_items = generated_map[key]

        for reference_component, generated_component in zip(
            reference_items,
            generated_items,
        ):
            all_fields = (
                set(reference_component.keys())
                | set(generated_component.keys())
            ) - ignored_component_fields

            for field in all_fields:
                reference_value = (
                    reference_component.get(field)
                )

                generated_value = (
                    generated_component.get(field)
                )

                if reference_value != generated_value:
                    field_difference_counts[field] = (
                        field_difference_counts.get(
                            field,
                            0,
                        )
                        + 1
                    )

    result["field_differences"] = (
        field_difference_counts
    )

    # -------------------------------------------------------------
    # PURL
    # -------------------------------------------------------------

    purl_differences = []

    for key in reference_keys & generated_keys:
        reference_component = reference_map[key][0]
        generated_component = generated_map[key][0]

        reference_purl = reference_component.get(
            "purl"
        )

        generated_purl = generated_component.get(
            "purl"
        )

        if reference_purl != generated_purl:
            purl_differences.append(
                {
                    "name": key[0],
                    "version": key[1],
                    "reference": reference_purl,
                    "generated": generated_purl,
                }
            )

    result["purl"] = {
        "difference_count": len(
            purl_differences
        ),
        "differences": sorted(
            purl_differences,
            key=lambda item: (
                item["name"],
                item["version"],
            ),
        ),
    }

    # -------------------------------------------------------------
    # External References
    # -------------------------------------------------------------

    def external_reference_stats(sbom):
        total = 0
        hashes = 0
        types = {}

        for component in sbom.get(
            "components",
            [],
        ):
            for external_reference in component.get(
                "externalReferences",
                [],
            ):
                total += 1

                reference_type = (
                    external_reference.get(
                        "type",
                        "<без type>",
                    )
                )

                types[reference_type] = (
                    types.get(
                        reference_type,
                        0,
                    )
                    + 1
                )

                if external_reference.get(
                    "hashes"
                ):
                    hashes += 1

        return {
            "total": total,
            "hashes": hashes,
            "types": types,
        }

    reference_external = (
        external_reference_stats(reference)
    )

    generated_external = (
        external_reference_stats(generated)
    )

    result["external_references"] = {
        "reference": reference_external,
        "generated": generated_external,
    }

    # -------------------------------------------------------------
    # Dependencies
    # -------------------------------------------------------------

    reference_dependencies = (
        reference.get(
            "dependencies",
            [],
        )
    )

    generated_dependencies = (
        generated.get(
            "dependencies",
            [],
        )
    )

    result["dependencies"] = {
        "reference_count": len(
            reference_dependencies
        ),
        "generated_count": len(
            generated_dependencies
        ),
        "count_matches": (
            len(reference_dependencies)
            == len(generated_dependencies)
        ),
        "refs_ignored": True,
    }

    return result


def compare_sbom_files(
    generated_path: str | Path,
    reference_path: str | Path,
) -> dict:
    """
    Загружает два JSON-файла и возвращает результат их сравнения.
    """

    generated_path = Path(generated_path)
    reference_path = Path(reference_path)

    with generated_path.open(
        "r",
        encoding="utf-8",
    ) as file:
        generated = json.load(file)

    with reference_path.open(
        "r",
        encoding="utf-8",
    ) as file:
        reference = json.load(file)

    return compare_sbom(
        generated,
        reference,
    )