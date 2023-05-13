from django.urls import path, re_path
from rest_framework.authtoken.views import obtain_auth_token
from . import views
from rest_framework.routers import DefaultRouter


router = DefaultRouter()

router.register(r'user', views.UserViewSet, basename='user')
urlpatterns = router.urls
urlpatterns += [
    path('login/', views.Login.as_view(), name='token-login'),

]
