import json
import tempfile

from django.contrib import messages
from django.core.paginator import Paginator
from django.http import JsonResponse
from django.shortcuts import redirect, render

from .forms import UploadFileForm
from .models import Component

from services.excel_service import import_excel_file
from services.url_service import get_valid_url


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
                import_excel_file(
                    temp_file_path
                )

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
        {
            "form": form,
        },
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

        if not isinstance(
            changes,
            list,
        ):
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
                            f"Компонент с ID "
                            f"{change['id']} "
                            "не найден."
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

    search_query = request.GET.get(
        "q",
        "",
    ).strip()

    only_links = (
        request.GET.get(
            "only_links"
        )
        == "1"
    )

    components = (
        Component.objects
        .all()
        .order_by("id")
    )

    if search_query:
        components = components.filter(
            external_references__icontains=search_query
        )

    if only_links:
        components = [
            component
            for component in components
            if get_valid_url(
                component.external_references
            )
        ]

    paginator = Paginator(
        components,
        200,
    )

    page_number = request.GET.get(
        "page"
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

    return render(
        request,
        "sbom/table.html",
        {
            "page_obj": page_obj,
            "search_query": search_query,
            "only_links": only_links,
        },
    )