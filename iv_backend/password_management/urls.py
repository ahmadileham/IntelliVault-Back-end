from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import GeneratedPasswordViewSet, PasswordAnalysisViewSet

router = DefaultRouter()
router.register(r'generated-password', GeneratedPasswordViewSet, basename='generated-password')
router.register(r'password-analysis', PasswordAnalysisViewSet, basename='password-analysis')

urlpatterns = [
    path('api/', include(router.urls)),
]
