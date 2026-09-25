from django.urls import path

from .views import component_list, upload_file


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
]