from django import forms
from django.forms import modelformset_factory

from .models import Component, UploadedFile


class UploadFileForm(forms.ModelForm):
    class Meta:
        model = UploadedFile
        fields = ["file"]
        labels = {
            "file": "Excel-файл",
        }


class ComponentForm(forms.ModelForm):
    class Meta:
        model = Component
        fields = [
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


ComponentFormSet = modelformset_factory(
    Component,
    form=ComponentForm,
    extra=0,
)
