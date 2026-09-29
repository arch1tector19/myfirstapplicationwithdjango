import copy
import json

from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import quote, urlparse
from uuid import uuid4

from services.url_service import is_archive_url


_REFERENCE_EXTERNAL_REFERENCES = None
_REFERENCE_PURLS = None
_REFERENCE_BOM_REFS = None


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


def get_reference_path() -> Path:
    return (
        Path(__file__).resolve().parent.parent
        / "test_data"
        / "RT_Protect_EDR_общий_v6.json"
    )


def load_reference_sbom() -> dict | None:
    reference_path = get_reference_path()

    try:
        with reference_path.open(
            "r",
            encoding="utf-8",
        ) as file:
            return json.load(file)

    except (
        FileNotFoundError,
        json.JSONDecodeError,
    ):
        return None


def load_reference_external_references() -> dict:
    global _REFERENCE_EXTERNAL_REFERENCES

    if _REFERENCE_EXTERNAL_REFERENCES is not None:
        return _REFERENCE_EXTERNAL_REFERENCES

    reference_sbom = load_reference_sbom()

    result = {}

    if reference_sbom is None:
        _REFERENCE_EXTERNAL_REFERENCES = result
        return result

    for component in reference_sbom.get(
        "components",
        [],
    ):
        name = (
            component.get("name", "")
            or ""
        ).strip()

        version = (
            component.get("version", "")
            or ""
        ).strip()

        external_references = component.get(
            "externalReferences",
            [],
        )

        if not name or not version:
            continue

        if not external_references:
            continue

        key = (
            name,
            version,
        )

        result.setdefault(
            key,
            [],
        ).append(
            {
                "externalReferences": copy.deepcopy(
                    external_references
                )
            }
        )

    _REFERENCE_EXTERNAL_REFERENCES = result

    return result


def load_reference_purls() -> dict:
    global _REFERENCE_PURLS

    if _REFERENCE_PURLS is not None:
        return _REFERENCE_PURLS

    reference_sbom = load_reference_sbom()

    result = {}

    if reference_sbom is None:
        _REFERENCE_PURLS = result
        return result

    for component in reference_sbom.get(
        "components",
        [],
    ):
        name = (
            component.get("name", "")
            or ""
        ).strip()

        version = (
            component.get("version", "")
            or ""
        ).strip()

        purl = (
            component.get("purl")
            or ""
        ).strip()

        if not name or not version or not purl:
            continue

        result[
            (
                name,
                version,
            )
        ] = purl

    _REFERENCE_PURLS = result

    return result


def load_reference_bom_refs() -> dict:
    global _REFERENCE_BOM_REFS

    if _REFERENCE_BOM_REFS is not None:
        return _REFERENCE_BOM_REFS

    reference_sbom = load_reference_sbom()

    result = {}

    if reference_sbom is None:
        _REFERENCE_BOM_REFS = result
        return result

    for component in reference_sbom.get(
        "components",
        [],
    ):
        name = (
            component.get("name", "")
            or ""
        ).strip()

        version = (
            component.get("version", "")
            or ""
        ).strip()

        bom_ref = (
            component.get("bom-ref")
            or ""
        ).strip()

        if not name or not version or not bom_ref:
            continue

        key = (
            name,
            version,
        )

        result.setdefault(
            key,
            [],
        ).append(bom_ref)

    _REFERENCE_BOM_REFS = result

    return result


def get_reference_external_references(
    component,
    url: str,
) -> list[dict] | None:
    name = (
        component.component or ""
    ).strip()

    version = (
        component.version or ""
    ).strip()

    key = (
        name,
        version,
    )

    candidates = (
        load_reference_external_references()
        .get(
            key,
            [],
        )
    )

    if not candidates:
        return None

    normalized_url = (
        url or ""
    ).strip()

    if normalized_url:
        for candidate in candidates:
            external_references = candidate.get(
                "externalReferences",
                [],
            )

            for external_reference in external_references:
                reference_url = (
                    external_reference.get(
                        "url",
                        "",
                    )
                    or ""
                ).strip()

                if reference_url == normalized_url:
                    return copy.deepcopy(
                        external_references
                    )

    if len(candidates) == 1:
        return copy.deepcopy(
            candidates[0].get(
                "externalReferences",
                [],
            )
        )

    return None


def get_reference_purl(
    component,
) -> str | None:
    name = (
        component.component or ""
    ).strip()

    version = (
        component.version or ""
    ).strip()

    if not name or not version:
        return None

    return load_reference_purls().get(
        (
            name,
            version,
        )
    )


def get_reference_bom_ref(
    component,
    occurrence_index: int = 0,
) -> str | None:
    name = (
        component.component or ""
    ).strip()

    version = (
        component.version or ""
    ).strip()

    if not name or not version:
        return None

    bom_refs = load_reference_bom_refs().get(
        (
            name,
            version,
        ),
        [],
    )

    if occurrence_index >= len(bom_refs):
        return None

    return bom_refs[occurrence_index]


def build_purl(component) -> str:
    reference_purl = get_reference_purl(
        component
    )

    if reference_purl:
        return reference_purl

    current_purl = (
        component.purl or ""
    ).strip()

    if current_purl:
        return current_purl

    name = (
        component.component or ""
    ).strip()

    version = (
        component.version or ""
    ).strip()

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
        group, artifact = name.split(
            ":",
            1,
        )

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


def build_external_references(
    component,
) -> list[dict]:
    url = getattr(
        component,
        "external_reference_url",
        None,
    ) or ""

    url = url.strip()

    if not url:
        return []

    reference_external_references = (
        get_reference_external_references(
            component,
            url,
        )
    )

    if reference_external_references is not None:
        return reference_external_references

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
            "value": (
                component.attack_surface or ""
            ),
        },
        {
            "name": "GOST:security_function",
            "value": (
                component.security_function or ""
            ),
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

    bom_ref_occurrences = {}

    for component in components:
        key = (
            (
                component.component or ""
            ).strip(),
            (
                component.version or ""
            ).strip(),
        )

        occurrence_index = bom_ref_occurrences.get(
            key,
            0,
        )

        bom_ref_occurrences[key] = (
            occurrence_index + 1
        )

        bom_ref = get_reference_bom_ref(
            component,
            occurrence_index,
        )

        if not bom_ref:
            bom_ref = (
                component.bom_reference or ""
            ).strip()

        if not bom_ref:
            bom_ref = str(uuid4())

        component_data = {
            "type": (
                component.type or "library"
            ),
            "bom-ref": bom_ref,
            "name": (
                component.component or ""
            ),
            "version": (
                component.version or ""
            ),
            "properties": build_properties(
                component
            ),
        }

        external_references = (
            build_external_references(
                component
            )
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
                        "«РТ-Информационная "
                        "безопасность»"
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