import random
import string
from rest_framework import viewsets, status
from rest_framework.response import Response
from .models import GeneratedPassword
from .serializers import GeneratedPasswordSerializer, PasswordCreateSerializer
from rest_framework.permissions import IsAuthenticated

# Helper function to generate password based on user preferences
def generate_password(length, use_uppercase, use_numbers, use_special_chars):
    characters = string.ascii_lowercase
    if use_uppercase:
        characters += string.ascii_uppercase
    if use_numbers:
        characters += string.digits
    if use_special_chars:
        characters += string.punctuation

    password = ''.join(random.choice(characters) for _ in range(length))
    return password

class GeneratedPasswordViewSet(viewsets.ModelViewSet):
    queryset = GeneratedPassword.objects.all()
    serializer_class = GeneratedPasswordSerializer
    permission_classes = [IsAuthenticated]

    def get_serializer_class(self):
        # Use a different serializer for password creation
        if self.action == 'create':
            return PasswordCreateSerializer
        return GeneratedPasswordSerializer

    def create(self, request, *args, **kwargs):
        # Validate user input using PasswordCreateSerializer
        create_serializer = self.get_serializer(data=request.data)
        create_serializer.is_valid(raise_exception=True)

        # Extract options from the request data
        length = request.data.get('length', 12)  # Default length is 12
        use_uppercase = request.data.get('use_uppercase', False)
        use_numbers = request.data.get('use_numbers', False)
        use_special_chars = request.data.get('use_special_chars', False)

        # Generate the password based on user preferences
        generated_password = generate_password(length, use_uppercase, use_numbers, use_special_chars)

        # Determine password strength (simple example: length-based)
        strength = length >= 12 and use_uppercase and use_numbers and use_special_chars

        # Save the generated password and its metadata
        password_instance = GeneratedPassword.objects.create(
            generated_by=request.user,  # Use the authenticated user for generated_by
            password=generated_password,
            strength=strength
        )

        # Return the created password with GeneratedPasswordSerializer
        response_serializer = GeneratedPasswordSerializer(password_instance)
        return Response(response_serializer.data, status=status.HTTP_201_CREATED)

    def list(self, request, *args, **kwargs):
        # Retrieve the recent passwords for the authenticated user
        queryset = self.get_queryset().filter(generated_by=request.user).order_by('-date_generated')[:10]
        serializer = self.get_serializer(queryset, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)
