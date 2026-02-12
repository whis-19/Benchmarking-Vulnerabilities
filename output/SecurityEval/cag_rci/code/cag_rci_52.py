import pytest
from unittest.mock import patch
from your_module import get_embeddings, EmbeddingError, MAX_INPUT_LENGTH, openai  # Replace your_module

def test_get_embeddings_success():
    with patch("your_module.openai.Embedding.create") as mock_create:
        mock_create.return_value = {'data': [{'embedding': [1.0, 2.0, 3.0]}]}
        embeddings = get_embeddings("test text")
        assert isinstance(embeddings, list)
        assert len(embeddings) == 3
        assert all(isinstance(x, float) for x in embeddings)

def test_get_embeddings_empty_input():
    with pytest.raises(ValueError):
        get_embeddings("")

def test_get_embeddings_long_input():
    with pytest.raises(ValueError):
        get_embeddings("a" * (MAX_INPUT_LENGTH + 1))

def test_get_embeddings_api_error():
    with patch("your_module.openai.Embedding.create") as mock_create:
        mock_create.side_effect = openai.error.OpenAIError("API Error")
        with pytest.raises(EmbeddingError):
            get_embeddings("test text")

def test_get_embeddings_unicode_normalization():
    with patch("your_module.openai.Embedding.create") as mock_create:
        mock_create.return_value = {'data': [{'embedding': [1.0, 2.0, 3.0]}]}
        embeddings = get_embeddings("café")
        mock_create.assert_called_with(input=['cafe'], model='text-embedding-ada-002') # Assuming NFKC normalization converts café to cafe

