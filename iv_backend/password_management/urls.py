from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import GeneratedPasswordViewSet, PasswordAnalysisViewSet, CheckBreachView, CheckSimilarityView

router = DefaultRouter()
router.register(r'generated-password', GeneratedPasswordViewSet, basename='generated-password')
router.register(r'password-analysis', PasswordAnalysisViewSet, basename='password-analysis')

urlpatterns = [
    path('api/', include(router.urls)),
    path('check-breach/', CheckBreachView.as_view(), name='check-breach'),
    path('check-similarity/', CheckSimilarityView.as_view(), name='check-similarity'),
]
