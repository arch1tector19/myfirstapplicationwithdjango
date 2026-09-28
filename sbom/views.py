import json
import tempfile
from pathlib import Path

from django.contrib import messages
from django.core.paginator import Paginator
from django.http import (
    HttpResponse,
    JsonResponse,
)
from django.shortcuts import (
    redirect,
    render,
)

from .forms import UploadFileForm
from .models import Component

from services.excel_service import (
    import_excel_file,
)
from services.sbom_service import (
    compare_sbom,
    generate_sbom_json,
)
from services.url_service import (
    get_valid_url,
    is_archive_url,
)


EDITABLE_FIELDS = [
    "component",
    "version",
    "type",
    "bom_reference",
    "purl",
    "external_references",
    "lang",
    "attack_surface",
    "security_function",
]


def upload_file(request):
    if request.method == "POST":
        form = UploadFileForm(
            request.POST,
            request.FILES,
        )

        if form.is_valid():
            uploaded_file = request.FILES["file"]

            with tempfile.NamedTemporaryFile(
                suffix=".xlsx",
                delete=False,
            ) as temp_file:
                for chunk in uploaded_file.chunks():
                    temp_file.write(chunk)

                temp_file_path = temp_file.name

            try:
                import_excel_file(temp_file_path)

                messages.success(
                    request,
                    "Excel-файл успешно загружен.",
                )

                return redirect(
                    "component_list"
                )

            except Exception as error:
                messages.error(
                    request,
                    str(error),
                )

        else:
            messages.error(
                request,
                "Не удалось загрузить файл.",
            )

    else:
        form = UploadFileForm()

    return render(
        request,
        "sbom/upload.html",
        {"form": form},
    )


def component_list(request):
    if request.method == "POST":
        try:
            changes = json.loads(
                request.body
            )

        except json.JSONDecodeError:
            return JsonResponse(
                {
                    "success": False,
                    "error": "Некорректный JSON.",
                },
                status=400,
            )

        if not isinstance(changes, list):
            return JsonResponse(
                {
                    "success": False,
                    "error": (
                        "Ожидался список изменений."
                    ),
                },
                status=400,
            )

        component_ids = []

        for change in changes:
            if "id" not in change:
                return JsonResponse(
                    {
                        "success": False,
                        "error": (
                            "Не указан ID компонента."
                        ),
                    },
                    status=400,
                )

            component_ids.append(
                change["id"]
            )

        components = Component.objects.in_bulk(
            component_ids
        )

        components_to_update = []

        for change in changes:
            component = components.get(
                change["id"]
            )

            if component is None:
                return JsonResponse(
                    {
                        "success": False,
                        "error": (
                            "Компонент с ID "
                            f"{change['id']} не найден."
                        ),
                    },
                    status=400,
                )

            for field in EDITABLE_FIELDS:
                if field in change:
                    setattr(
                        component,
                        field,
                        str(change[field]),
                    )

            components_to_update.append(
                component
            )

        if components_to_update:
            Component.objects.bulk_update(
                components_to_update,
                EDITABLE_FIELDS,
            )

        return JsonResponse(
            {
                "success": True,
                "updated": len(
                    components_to_update
                ),
            }
        )

    components = (
        Component.objects
        .all()
        .order_by("id")
    )

    paginator = Paginator(
        components,
        200,
    )

    page_number = request.GET.get(
        "page",
        1,
    )

    page_obj = paginator.get_page(
        page_number
    )

    for component in page_obj:
        component.external_reference_url = (
            get_valid_url(
                component.external_references
            )
        )

        component.external_reference_is_archive = (
            is_archive_url(
                component.external_reference_url
            )
        )

    return render(
        request,
        "sbom/table.html",
        {
            "page_obj": page_obj,
        },
    )


def generate_sbom(request):
    components = list(
        Component.objects
        .all()
        .order_by("id")
    )

    for component in components:
        component.external_reference_url = (
            get_valid_url(
                component.external_references
            )
        )

    sbom_json = generate_sbom_json(
        components
    )

    response = HttpResponse(
        sbom_json,
        content_type=(
            "application/json; charset=utf-8"
        ),
    )

    response["Content-Disposition"] = (
        'attachment; '
        'filename="RT_Protect_EDR_SBOM.json"'
    )

    return response


def compare_sbom_with_reference(request):
    """
    Временная функция для проверки
    сформированного SBOM относительно эталона.
    """

    components = list(
        Component.objects
        .all()
        .order_by("id")
    )

    for component in components:
        component.external_reference_url = (
            get_valid_url(
                component.external_references
            )
        )

    try:
        generated_sbom = json.loads(
            generate_sbom_json(
                components
            )
        )

        reference_path = (
            Path(__file__).resolve()
            .parent.parent
            / "test_data"
            / "RT_Protect_EDR_общий_v6.json"
        )

        with reference_path.open(
            "r",
            encoding="utf-8",
        ) as file:
            reference_sbom = json.load(file)

        comparison_result = compare_sbom(
            generated_sbom,
            reference_sbom,
        )

    except FileNotFoundError:
        messages.error(
            request,
            "Эталонный SBOM не найден.",
        )

        return redirect(
            "component_list"
        )

    except json.JSONDecodeError:
        messages.error(
            request,
            (
                "Эталонный SBOM содержит "
                "некорректный JSON."
            ),
        )

        return redirect(
            "component_list"
        )

    except Exception as error:
        messages.error(
            request,
            f"Ошибка сравнения SBOM: {error}",
        )

        return redirect(
            "component_list"
        )

    components_queryset = (
        Component.objects
        .all()
        .order_by("id")
    )

    paginator = Paginator(
        components_queryset,
        200,
    )

    page_number = request.GET.get(
        "page",
        1,
    )

    page_obj = paginator.get_page(
        page_number
    )

    for component in page_obj:
        component.external_reference_url = (
            get_valid_url(
                component.external_references
            )
        )

        component.external_reference_is_archive = (
            is_archive_url(
                component.external_reference_url
            )
        )

    top_level_matches = all(
        item["matches"]
        for item in comparison_result[
            "top_level"
        ].values()
    )

    metadata_matches = (
        comparison_result[
            "metadata"
        ]["tools"]["matches"]
        and not comparison_result[
            "metadata"
        ]["component_differences"]
    )

    components_matches = (
        comparison_result[
            "components"
        ]["count_matches"]
        and not comparison_result[
            "components"
        ]["only_in_reference"]
        and not comparison_result[
            "components"
        ]["only_in_generated"]
    )

    dependencies_matches = (
        comparison_result[
            "dependencies"
        ]["count_matches"]
    )

    field_matches = not comparison_result[
        "field_differences"
    ]

    purl_matches = (
        comparison_result[
            "purl"
        ]["difference_count"]
        == 0
    )

    external_reference_data = (
        comparison_result[
            "external_references"
        ]
    )

    external_reference_matches = (
        external_reference_data[
            "reference"
        ]
        == external_reference_data[
            "generated"
        ]
    )

    comparison_matches = (
        top_level_matches
        and metadata_matches
        and components_matches
        and dependencies_matches
        and field_matches
        and purl_matches
        and external_reference_matches
    )

    reference_types = (
        external_reference_data[
            "reference"
        ]["types"]
    )

    generated_types = (
        external_reference_data[
            "generated"
        ]["types"]
    )

    reference_types_text = ", ".join(
        f"{name} — {count}"
        for name, count
        in reference_types.items()
    )

    generated_types_text = ", ".join(
        f"{name} — {count}"
        for name, count
        in generated_types.items()
    )

    comparison_rows = [
        {
            "label": "Количество компонентов",
            "reference": (
                comparison_result[
                    "components"
                ]["reference_count"]
            ),
            "generated": (
                comparison_result[
                    "components"
                ]["generated_count"]
            ),
        },
        {
            "label": "Dependencies",
            "reference": (
                comparison_result[
                    "dependencies"
                ]["reference_count"]
            ),
            "generated": (
                comparison_result[
                    "dependencies"
                ]["generated_count"]
            ),
        },
        {
            "label": "PURL: отличий",
            "reference": "—",
            "generated": (
                comparison_result[
                    "purl"
                ]["difference_count"]
            ),
        },
        {
            "label": "External References",
            "reference": (
                external_reference_data[
                    "reference"
                ]["total"]
            ),
            "generated": (
                external_reference_data[
                    "generated"
                ]["total"]
            ),
        },
        {
            "label": "References с hashes",
            "reference": (
                external_reference_data[
                    "reference"
                ]["hashes"]
            ),
            "generated": (
                external_reference_data[
                    "generated"
                ]["hashes"]
            ),
        },
    ]

    comparison_display = {
        "comparison_matches": comparison_matches,

        "rows": comparison_rows,

        "bom_format": generated_sbom.get(
            "bomFormat"
        ),

        "spec_version": generated_sbom.get(
            "specVersion"
        ),

        "version": generated_sbom.get(
            "version"
        ),

        "purl_difference_count": (
            comparison_result[
                "purl"
            ]["difference_count"]
        ),

        "external_reference_difference_count": (
            comparison_result[
                "field_differences"
            ].get(
                "externalReferences",
                0,
            )
        ),

        "reference_types_text": (
            reference_types_text
        ),

        "generated_types_text": (
            generated_types_text
        ),

        "reference_external_total": (
            external_reference_data[
                "reference"
            ]["total"]
        ),

        "generated_external_total": (
            external_reference_data[
                "generated"
            ]["total"]
        ),

        "reference_hashes": (
            external_reference_data[
                "reference"
            ]["hashes"]
        ),

        "generated_hashes": (
            external_reference_data[
                "generated"
            ]["hashes"]
        ),
    }

    return render(
        request,
        "sbom/table.html",
        {
            "page_obj": page_obj,
            "comparison_display": (
                comparison_display
            ),
        },
    )