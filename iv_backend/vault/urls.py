from django.urls import include, path
from rest_framework.routers import DefaultRouter
from .views import VaultViewSet, LoginInfoViewSet, FileViewSet, ShareItemView, ShareVaultView, AccessSharedItemView, AccessSharedVaultView, FileDownloadView

router = DefaultRouter()
router.register(r'vault', VaultViewSet, basename='vault')
router.register(r'logininfo', LoginInfoViewSet, basename='login-info')
router.register(r'file', FileViewSet, basename='file')

urlpatterns = [
    path('api/', include(router.urls)),
    path('file/download/<int:file_id>/', FileDownloadView.as_view(), name='file-download-owner'),
    path('file/download/<int:file_id>/<str:share_link>/', FileDownloadView.as_view(), name='file-download-shared'),
    # Sharing URLs
    path('share/item/<int:item_id>/', ShareItemView.as_view(), name='share-item'),
    path('share/vault/<int:vault_id>/', ShareVaultView.as_view(), name='share-vault'),
    
    # Accessing Shared Items/Vaults
    path('access/item/<str:share_link>/', AccessSharedItemView.as_view(), name='access-shared-item'),
    path('access/vault/<str:share_link>/', AccessSharedVaultView.as_view(), name='access-shared-vault'),

]
