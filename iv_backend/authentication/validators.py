import re
from django.core.exceptions import ValidationError
from django.utils.translation import gettext as _

class CustomPasswordValidator:
    def validate(self, password, user=None):
        errors = []

        if len(password) < 8:
            errors.append(_("Password must be at least 8 characters long."))

        if not re.search(r'[A-Z]', password):
            errors.append(_("Password is missing at least one uppercase letter."))

        if not re.search(r'[a-z]', password):
            errors.append(_("Password is missing at least one lowercase letter."))

        if not re.search(r'[0-9]', password):
            errors.append(_("Password is missing at least one number."))

        if not re.search(r'[\W_]', password):  # \W matches any non-alphanumeric character (special characters)
            errors.append(_("Password is missing at least one special character."))

        if errors:
            raise ValidationError(errors)

    def get_help_text(self):
        return _(
            "Your password must contain at least 8 characters, including at least one uppercase letter, "
            "one lowercase letter, one number, and one special character."
        )
