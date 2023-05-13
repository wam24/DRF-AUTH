from django.conf import settings
from django.contrib.auth.tokens import PasswordResetTokenGenerator
# from django.core.urlresolvers import reverse
from django.utils import six
from django.utils.encoding import force_bytes
from django.utils.http import urlsafe_base64_encode
from rest_framework.reverse import reverse


class TokenGenerator(PasswordResetTokenGenerator):
    def _make_hash_value(self, user, timestamp):
        return (
                six.text_type(user.pk) + six.text_type(timestamp)
        )


account_activation_token = TokenGenerator()


def get_activation_url(user, reset_password=None):
    """
    Retorna url para activar o cambiar contraseña
    :param user:
    :param reset_password:
    :return:
    """
    uid = urlsafe_base64_encode(force_bytes(user.pk))
    token = account_activation_token.make_token(user)
    if settings.DEBUG:
        print(uid, token)
    if not reset_password:
        return f"/auth/active/{uid}/{token}/" if not settings.CREATE_WEB_HASH_HISTORY_FRONTEND \
            else f"/#/auth/active/{uid}/{token}/"
    else:
        return f"/auth/password_reset/{uid}/{token}/" if not settings.CREATE_WEB_HASH_HISTORY_FRONTEND \
            else f"/#/auth/password_reset/{uid}/{token}/"
