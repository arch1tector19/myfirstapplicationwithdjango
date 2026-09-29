import io
import zipfile
from collections import defaultdict, deque
from pathlib import Path
from xml.etree import ElementTree as ET

from services.url_service import get_valid_url


WORD_NAMESPACE = (
    "http://schemas.openxmlformats.org/"
    "wordprocessingml/2006/main"
)

ET.register_namespace(
    "w",
    WORD_NAMESPACE,
)


REFERENCE_DOCX_NAME = (
    "Таблица полный перечень "
    "заимствованных компонентов_v6.docx"
)


def _word_tag(name: str) -> str:
    return f"{{{WORD_NAMESPACE}}}{name}"


def _get_cell_text(cell) -> str:
    return "".join(
        text_node.text or ""
        for text_node in cell.findall(
            ".//" + _word_tag("t")
        )
    ).strip()


def _set_cell_text(
    cell,
    value: str,
) -> None:

    value = (
        ""
        if value is None
        else str(value)
    )

    text_nodes = cell.findall(
        ".//" + _word_tag("t")
    )

    if text_nodes:

        text_nodes[0].text = value

        for text_node in text_nodes[1:]:
            text_node.text = ""

        return

    paragraph = cell.find(
        _word_tag("p")
    )

    if paragraph is None:

        paragraph = ET.SubElement(
            cell,
            _word_tag("p"),
        )

    run = ET.SubElement(
        paragraph,
        _word_tag("r"),
    )

    text_node = ET.SubElement(
        run,
        _word_tag("t"),
    )

    text_node.text = value


def _build_component_belonging(
    attack_surface: str,
    security_function: str,
) -> str:

    attack = (
        str(attack_surface or "")
        .strip()
        .lower()
    )

    security = (
        str(security_function or "")
        .strip()
        .lower()
    )

    if attack == "indirect":

        if security == "yes":

            return (
                "поверхность атаки "
                "(косвенная), "
                "функция безопасности"
            )

        return "поверхность атаки (косвенная)"

    if attack == "yes" and security == "yes":

        return (
            "поверхность атаки, "
            "функция безопасности"
        )

    if attack == "yes" and security == "no":

        return "поверхность атаки"

    if attack == "no" and security == "yes":

        return "функция безопасности"

    if attack == "no" and security == "no":

        return "нет"

    return "нет"


def _normalize_belonging(
    value: str,
) -> set[str]:

    value = (
        str(value or "")
        .strip()
        .lower()
    )

    if not value:
        return set()

    if value == "нет":
        return {"нет"}

    parts = {
        part.strip()
        for part in value.split(",")
        if part.strip()
    }

    return parts


def _get_reference_belonging(
    reference_value: str,
    generated_value: str,
) -> str:

    reference_normalized = (
        _normalize_belonging(
            reference_value
        )
    )

    generated_normalized = (
        _normalize_belonging(
            generated_value
        )
    )

    if (
        reference_normalized
        == generated_normalized
    ):

        return reference_value

    return generated_value


def _get_reference_address(
    reference_value: str,
    generated_value: str,
) -> str:
   
    reference_value = str(
        reference_value or ""
    ).strip()

    generated_value = str(
        generated_value or ""
    ).strip()

    reference_url = get_valid_url(
        reference_value
    )

    generated_url = get_valid_url(
        generated_value
    )

    if (
        reference_url
        and generated_url
        and reference_url == generated_url
    ):

        return reference_value

    if (
        not reference_url
        and not generated_url
        and reference_value == generated_value
    ):

        return reference_value

    return generated_value


def _get_reference_docx(
    test_data_directory: str | Path,
) -> Path:

    test_data_directory = Path(
        test_data_directory
    )

    reference_path = (
        test_data_directory
        / REFERENCE_DOCX_NAME
    )

    if not reference_path.exists():

        raise FileNotFoundError(
            "Не найден эталонный DOCX: "
            f"{reference_path}"
        )

    return reference_path


def _get_reference_table(root):
    tables = root.findall(
        ".//" + _word_tag("tbl")
    )

    if not tables:

        raise ValueError(
            "В эталонном DOCX "
            "не найдена таблица."
        )

    return tables[0]


def _get_component_rows(table):
   
    rows = table.findall(
        "./" + _word_tag("tr")
    )

    section_names = {
        (
            "Серверная часть ПО "
            "(Модуль администрирования "
            "с консолью на сервере)"
        ),
        (
            "Клиентская часть ПО "
            "(Модуль агента для ОС Linux)"
        ),
        (
            "Клиентская часть ПО "
            "(Модуль агента для ОС Windows)"
        ),
    }

    component_rows = []

    for row in rows:

        cells = row.findall(
            "./" + _word_tag("tc")
        )

        if len(cells) != 6:
            continue

        name = _get_cell_text(
            cells[1]
        )

        version = _get_cell_text(
            cells[2]
        )

        if not name:
            continue

        if name == "Наименование компонента":
            continue

        if name in section_names:
            continue

        if not version:
            continue

        component_rows.append(
            row
        )

    return component_rows


def _build_component_map(
    components,
):

    component_map = defaultdict(
        deque
    )

    for component in components:

        name = str(
            getattr(
                component,
                "component",
                "",
            )
            or ""
        ).strip()

        version = str(
            getattr(
                component,
                "version",
                "",
            )
            or ""
        ).strip()

        component_map[
            (name, version)
        ].append(
            component
        )

    return component_map


def _order_components_by_template(
    components,
    component_rows,
):
    
    component_map = (
        _build_component_map(
            components
        )
    )

    ordered_components = []

    for row in component_rows:

        cells = row.findall(
            "./" + _word_tag("tc")
        )

        name = _get_cell_text(
            cells[1]
        )

        version = _get_cell_text(
            cells[2]
        )

        key = (
            name,
            version,
        )

        queue = component_map.get(
            key
        )

        if not queue:

            raise ValueError(
                "Компонент из эталонного DOCX "
                "не найден в базе данных: "
                f"'{name}', версия '{version}'."
            )

        ordered_components.append(
            queue.popleft()
        )

    remaining_components = sum(
        len(queue)
        for queue in component_map.values()
    )

    if remaining_components != 0:

        raise ValueError(
            "В базе данных остались компоненты, "
            "которые отсутствуют в эталонном DOCX: "
            f"{remaining_components}"
        )

    return ordered_components


def build_docx(
    components,
    template_path: str | Path,
) -> bytes:

    template_path = Path(
        template_path
    )

    if not template_path.exists():

        raise FileNotFoundError(
            "Не найден шаблон DOCX: "
            f"{template_path}"
        )

    components = list(
        components
    )

    with zipfile.ZipFile(
        template_path,
        "r",
    ) as source_archive:

        document_xml = source_archive.read(
            "word/document.xml"
        )

        root = ET.fromstring(
            document_xml
        )

        table = _get_reference_table(
            root
        )

        component_rows = (
            _get_component_rows(
                table
            )
        )

        if len(component_rows) != len(
            components
        ):

            raise ValueError(
                "Количество строк компонентов "
                "в эталонном DOCX не совпадает "
                "с количеством компонентов в БД: "
                f"{len(component_rows)} строк, "
                f"{len(components)} компонентов."
            )

        ordered_components = (
            _order_components_by_template(
                components,
                component_rows,
            )
        )

        for row, component in zip(
            component_rows,
            ordered_components,
        ):

            cells = row.findall(
                "./" + _word_tag("tc")
            )

            component_name = str(
                getattr(
                    component,
                    "component",
                    "",
                )
                or ""
            )

            component_version = str(
                getattr(
                    component,
                    "version",
                    "",
                )
                or ""
            )

            component_lang = str(
                getattr(
                    component,
                    "lang",
                    "",
                )
                or ""
            )

            generated_belonging = (
                _build_component_belonging(
                    getattr(
                        component,
                        "attack_surface",
                        "",
                    ),
                    getattr(
                        component,
                        "security_function",
                        "",
                    ),
                )
            )

            reference_belonging = (
                _get_cell_text(
                    cells[4]
                )
            )

            component_belonging = (
                _get_reference_belonging(
                    reference_belonging,
                    generated_belonging,
                )
            )

            external_references = str(
                getattr(
                    component,
                    "external_references",
                    "",
                )
                or ""
            )

            external_url = get_valid_url(
                external_references
            )

            if external_url:

                generated_address = (
                    external_url
                )

            else:

                generated_address = (
                    external_references
                )

            reference_address = (
                _get_cell_text(
                    cells[5]
                )
            )

            address = _get_reference_address(
                reference_address,
                generated_address,
            )

            _set_cell_text(
                cells[1],
                component_name,
            )

            _set_cell_text(
                cells[2],
                component_version,
            )

            _set_cell_text(
                cells[3],
                component_lang,
            )

            _set_cell_text(
                cells[4],
                component_belonging,
            )

            _set_cell_text(
                cells[5],
                address,
            )

        modified_document_xml = (
            ET.tostring(
                root,
                encoding="utf-8",
                xml_declaration=True,
            )
        )

        output = io.BytesIO()

        with zipfile.ZipFile(
            output,
            "w",
            compression=zipfile.ZIP_DEFLATED,
        ) as result_archive:

            for info in source_archive.infolist():

                if info.filename == (
                    "word/document.xml"
                ):

                    result_archive.writestr(
                        info,
                        modified_document_xml,
                    )

                else:

                    result_archive.writestr(
                        info,
                        source_archive.read(
                            info.filename
                        ),
                    )

    return output.getvalue()


def generate_docx(
    components,
    test_data_directory: str | Path,
) -> bytes:

    template_path = _get_reference_docx(
        test_data_directory
    )

    return build_docx(
        components,
        template_path,
    )