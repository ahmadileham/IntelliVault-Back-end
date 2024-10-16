from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import GeneratedPasswordViewSet

router = DefaultRouter()
router.register(r'generated-password', GeneratedPasswordViewSet, basename='generated-password')

urlpatterns = [
    path('api/', include(router.urls)),
]
