from django.template.loader import render_to_string


def send_email_user_activation(user, name, to_email, subject, template_name, domain_frontend=True,
                               reset_password=False, password=False):
    from django.contrib.sites.models import Site
    from .tokens import get_activation_url
    from django.conf import settings
    from django.core.mail.message import EmailMessage

    current_site = Site.objects.first()
    activation_url = get_activation_url(user=user, reset_password=reset_password)

    if domain_frontend:
        domain = settings.FRONTEND_DOMAIN
    else:
        domain = current_site.domain
    protocolo = "https"

    if settings.DEBUG:
        print("http://{domain}{activation_url}".format(domain=domain,
                                                       activation_url=activation_url))
        protocolo = "http"
    context = {
        'fullName': name,
        'to': to_email,
        'domain_static': current_site.domain,
        'domain': domain,
        'baseUrl': settings.FRONTEND_DOMAIN,
        'activation_url': activation_url,
        'password': password,
        "protocolo": protocolo

    }
    context_template = render_to_string(template_name=template_name, context=context)
    context['body'] = context_template
    context['to'] = to_email
    context['baseUrl'] = settings.FRONTEND_DOMAIN
    message = render_to_string(template_name='email/base-template-email.html', context=context)
    email = EmailMessage(
        subject, message, to=[to_email],
    )
    email.content_subtype = 'html'
    email.send()