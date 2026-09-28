from django.urls import path

from .views import (
    component_list,
    generate_docx_file,
    generate_sbom,
    upload_file,
)


urlpatterns = [
    path(
        "",
        upload_file,
        name="upload_file",
    ),
    path(
        "components/",
        component_list,
        name="component_list",
    ),
    path(
        "components/generate-sbom/",
        generate_sbom,
        name="generate_sbom",
    ),
    path(
        "components/generate-docx/",
        generate_docx_file,
        name="generate_docx",
    ),
]