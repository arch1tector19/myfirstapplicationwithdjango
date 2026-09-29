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

from services.docx_service import (
    generate_docx,
)

from services.excel_service import (
    import_excel_file,
)

from services.sbom_service import (
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

                    temp_file.write(
                        chunk
                    )

                temp_file_path = (
                    temp_file.name
                )

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


def generate_docx_file(request):


    components = list(
        Component.objects
        .all()
        .order_by("id")
    )

    test_data_directory = (
        Path(__file__).resolve().parent.parent
        / "test_data"
    )

    try:

        docx_data = generate_docx(
            components,
            test_data_directory,
        )

    except Exception as error:

        messages.error(
            request,
            f"Ошибка формирования DOCX: {error}",
        )

        return redirect(
            "component_list"
        )

    response = HttpResponse(
        docx_data,
        content_type=(
            "application/vnd.openxmlformats-"
            "officedocument.wordprocessingml.document"
        ),
    )

    response["Content-Disposition"] = (
        'attachment; '
        'filename="RT_Protect_EDR_components.docx"'
    )

    return response