from django.db import models


class UploadedFile(models.Model):
    file = models.FileField(upload_to="uploads/")
    original_name = models.CharField(max_length=255)
    uploaded_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.original_name


class Component(models.Model):
    uploaded_file = models.ForeignKey(
        UploadedFile,
        on_delete=models.CASCADE,
        related_name="components",
        null=True,
        blank=True,
    )

    component = models.CharField(max_length=255)
    version = models.CharField(max_length=255, blank=True)
    type = models.CharField(max_length=100, blank=True)
    bom_reference = models.CharField(max_length=255, blank=True)
    purl = models.TextField(blank=True)
    external_references = models.TextField(blank=True)
    lang = models.CharField(max_length=100, blank=True)
    attack_surface = models.CharField(max_length=50, blank=True)
    security_function = models.CharField(max_length=50, blank=True)

    def __str__(self):
        return self.component

    class Meta:
        ordering = ["id"]