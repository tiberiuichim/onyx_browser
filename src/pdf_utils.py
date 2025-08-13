import io
import logging
import requests
from collections.abc import Sequence
from typing import Any, IO
from PIL import Image
from pypdf import PdfReader
from pypdf.errors import PdfStreamError

logger = logging.getLogger("debug")

TEXT_SECTION_SEPARATOR = "\n\n"

# Common PDF MIME types
PDF_MIME_TYPES = [
    "application/pdf",
    "application/x-pdf",
    "application/acrobat",
    "application/vnd.pdf",
    "text/pdf",
    "text/x-pdf",
]


def read_pdf_file(
    file: IO[Any], pdf_pass: str | None = None, extract_images: bool = False
) -> tuple[str, dict[str, Any], Sequence[tuple[bytes, str]]]:
    """
    Returns the text, basic PDF metadata, and optionally extracted images.
    """
    metadata: dict[str, Any] = {}
    extracted_images: list[tuple[bytes, str]] = []
    try:
        pdf_reader = PdfReader(file)

        if pdf_reader.is_encrypted and pdf_pass is not None:
            decrypt_success = False
            try:
                decrypt_success = pdf_reader.decrypt(pdf_pass) != 0
            except Exception:
                logger.error("Unable to decrypt pdf")

            if not decrypt_success:
                return "", metadata, []
        elif pdf_reader.is_encrypted:
            logger.warning(
                "No Password for an encrypted PDF, returning empty text.")
            return "", metadata, []

        # Basic PDF metadata
        if pdf_reader.metadata is not None:
            for key, value in pdf_reader.metadata.items():
                clean_key = key.lstrip("/")
                if isinstance(value, str) and value.strip():
                    metadata[clean_key] = value
                elif isinstance(value, list) and all(
                    isinstance(item, str) for item in value
                ):
                    metadata[clean_key] = ", ".join(value)

        text = TEXT_SECTION_SEPARATOR.join(
            page.extract_text() for page in pdf_reader.pages
        )

        if extract_images:
            for page_num, page in enumerate(pdf_reader.pages):
                for image_file_object in page.images:
                    image = Image.open(io.BytesIO(image_file_object.data))
                    img_byte_arr = io.BytesIO()
                    image.save(img_byte_arr, format=image.format)
                    img_bytes = img_byte_arr.getvalue()

                    image_name = (
                        f"""page_{page_num + 1}
                            _image_{image_file_object.name}."""
                        f"""{image.format.lower() if image.format else "png"}"""
                    )
                    extracted_images.append((img_bytes, image_name))

        return text, metadata, extracted_images

    except PdfStreamError:
        logger.exception("Invalid PDF file")
    except Exception:
        logger.exception("Failed to read PDF")

    return "", metadata, []


def is_pdf_content(response: requests.Response) -> bool:
    """Check if the response contains PDF content based on content-type header"""
    content_type = response.headers.get("content-type", "").lower()
    return any(pdf_type in content_type for pdf_type in PDF_MIME_TYPES)
