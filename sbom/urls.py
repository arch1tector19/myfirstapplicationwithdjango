from django.urls import path

from .views import (
    compare_sbom_with_reference,
    component_list,
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
        "components/compare-sbom/",
        compare_sbom_with_reference,
        name="compare_sbom",
    ),
]