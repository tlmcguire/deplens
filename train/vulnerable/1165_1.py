from django.db import models

class Media(models.Model):
    file = models.FileField()

    def save(self, *args, **kwargs):
        super().save(*args, **kwargs)