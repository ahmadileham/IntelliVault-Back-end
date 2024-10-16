from django.urls import include, path
from rest_framework.routers import DefaultRouter
from .views import VaultViewSet, LoginInfoViewSet, FileViewSet

router = DefaultRouter()
router.register(r'vault', VaultViewSet, basename='vault')
router.register(r'logininfo', LoginInfoViewSet, basename='login-info')
router.register(r'file', FileViewSet, basename='file')

urlpatterns = [
    path('api/', include(router.urls)),
]
