import os
import json
import tempfile

import pytest
from extract_and_visualize_v2 import update_html_template

START_MARKER = '// ===== DATA SECTION (replaced by Python script) ====='
END_MARKER = '// ===== END DATA SECTION ====='


def _write_template(tmpdir, content):
    path = os.path.join(str(tmpdir), 'template.html')
    with open(path, 'w', encoding='utf-8') as f:
        f.write(content)
    return path


class TestUpdateHtmlTemplate:

    def test_markers_replaced(self, tmp_path):
        template = (
            '<html><script>\n'
            '{start}\n'
            '    const nodesData = [];\n'
            '{end}\n'
            '</script></html>'
        ).format(start=START_MARKER, end=END_MARKER)

        path = _write_template(tmp_path, template)
        nodes = [{'id': 'n1'}]
        edges = [{'from': 'n1', 'to': 'n2'}]

        result = update_html_template(path, nodes, edges, {}, {}, {})

        assert START_MARKER in result
        assert END_MARKER in result
        assert '"n1"' in result
        assert 'nodesData' in result
        assert 'edgesData' in result
        assert 'sgRules' in result

    def test_missing_start_marker(self, tmp_path):
        path = _write_template(tmp_path, '<html>no markers here</html>')

        with pytest.raises(ValueError):
            update_html_template(path, [], [], {}, {}, {})

    def test_json_encoding(self, tmp_path):
        template = (
            '<html><script>\n'
            '{start}\n'
            '{end}\n'
            '</script></html>'
        ).format(start=START_MARKER, end=END_MARKER)

        path = _write_template(tmp_path, template)
        nodes = [{'label': '서울 리전 테스트'}]

        result = update_html_template(path, nodes, [], {}, {}, {})

        assert '서울 리전 테스트' in result

    def test_empty_data(self, tmp_path):
        template = (
            '{start}\n'
            '{end}'
        ).format(start=START_MARKER, end=END_MARKER)

        path = _write_template(tmp_path, template)
        result = update_html_template(path, [], [], {}, {}, {})

        assert 'nodesData = []' in result
        assert 'edgesData = []' in result
        assert 'sgRules = {}' in result
