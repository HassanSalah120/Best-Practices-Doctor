from __future__ import annotations

from rules.react.animation_no_pause_control import AnimationNoPauseControlRule
from rules.react.focus_lost_on_route_change import FocusLostOnRouteChangeRule
from rules.react.form_double_submit import FormDoubleSubmitRule
from rules.react.input_debounce_missing import InputDebounceMissingRule
from rules.react.missing_error_boundary_general import MissingErrorBoundaryGeneralRule
from rules.react.missing_fieldset_legend import MissingFieldsetLegendRule
from rules.react.missing_list_virtualization import MissingListVirtualizationRule
from rules.react.missing_route_code_splitting import MissingRouteCodeSplittingRule
from rules.react.table_missing_headers import TableMissingHeadersRule
from rules.react.unhandled_promise_in_handler import UnhandledPromiseInHandlerRule
from rules.react.unthrottled_scroll_resize_handler import UnthrottledScrollResizeHandlerRule
from rules.react.video_missing_captions import VideoMissingCaptionsRule
from schemas.facts import Facts


def _facts() -> Facts:
    return Facts(project_path=".")


def test_unthrottled_scroll_resize_handler_valid_invalid_fp_guard():
    rule = UnthrottledScrollResizeHandlerRule()
    valid = "useEffect(() => { window.addEventListener('scroll', throttle(onScroll, 100)); }, []);"
    invalid = "useEffect(() => { window.addEventListener('scroll', expensiveHandler); }, []);"
    fp_guard = "useEffect(() => { window.addEventListener('resize', onResize); return () => window.removeEventListener('resize', onResize); }, []);"

    assert rule.analyze_regex("src/hooks/useScroll.ts", valid, _facts()) == []
    assert len(rule.analyze_regex("src/hooks/useScroll.ts", invalid, _facts())) == 1
    assert rule.analyze_regex("src/hooks/useResize.ts", fp_guard, _facts()) == []


def test_missing_list_virtualization_valid_invalid_fp_guard():
    rule = MissingListVirtualizationRule()
    valid = "import { FixedSizeList } from 'react-window';\n{users.map(u => <UserRow key={u.id} user={u}/>)}"
    invalid = "export function Users() { return <>{allUsers.map(u => <UserRow key={u.id} user={u}/>)}</>; }"
    fp_guard = "export function Tags() { return <>{tags.map(t => <span>{t}</span>)}</>; }"

    assert rule.analyze_regex("src/pages/Users.tsx", valid, _facts()) == []
    assert len(rule.analyze_regex("src/pages/Users.tsx", invalid, _facts())) == 1
    assert rule.analyze_regex("src/components/Tags.tsx", fp_guard, _facts()) == []


def test_input_debounce_missing_valid_invalid_fp_guard():
    rule = InputDebounceMissingRule()
    valid = "const onSearch = debounce((e) => fetchResults(e.target.value), 300);\n<input onChange={onSearch} />"
    invalid = "<input onChange={e => fetchResults(e.target.value)} />"
    fp_guard = "<input type=\"checkbox\" onChange={e => fetchResults(e.target.checked)} />"

    assert rule.analyze_regex("src/components/Search.tsx", valid, _facts()) == []
    assert len(rule.analyze_regex("src/components/Search.tsx", invalid, _facts())) == 1
    assert rule.analyze_regex("src/components/Toggle.tsx", fp_guard, _facts()) == []


def test_missing_route_code_splitting_valid_invalid_fp_guard():
    rule = MissingRouteCodeSplittingRule()
    valid = "const Dashboard = React.lazy(() => import('./pages/Dashboard'));"
    invalid = "\n".join([f"import Page{i} from './pages/Page{i}';" for i in range(6)]) + "\nexport const routes = [];"
    fp_guard = "import { resolvePageComponent } from 'laravel-vite-plugin/inertia-helpers';\n" + invalid

    assert rule.analyze_regex("src/routes.tsx", valid, _facts()) == []
    assert len(rule.analyze_regex("src/routes.tsx", invalid, _facts())) == 1
    assert rule.analyze_regex("src/routes.tsx", fp_guard, _facts()) == []


def test_missing_error_boundary_general_valid_invalid_fp_guard():
    rule = MissingErrorBoundaryGeneralRule()
    valid = "export function Widget(){ return <ErrorBoundary><Chart /></ErrorBoundary>; }"
    invalid = "export function Dashboard(){\n" + "const x = 1;\n" * 55 + "fetch('/api');\nreturn <Chart />;\n}"
    fp_guard = "export function Small(){ fetch('/api'); return <div/>; }"

    assert rule.analyze_regex("src/pages/Dashboard.tsx", valid, _facts()) == []
    assert len(rule.analyze_regex("src/pages/Dashboard.tsx", invalid, _facts())) == 1
    assert rule.analyze_regex("src/components/Small.tsx", fp_guard, _facts()) == []


def test_unhandled_promise_in_handler_valid_invalid_fp_guard():
    rule = UnhandledPromiseInHandlerRule()
    valid = "const handleSave = async () => {\ntry { await save(data); } catch (e) { setError(e); }\n}"
    invalid = "const handleSave = async () => {\nawait save(data);\n}"
    fp_guard = "const mutation = useMutation(save);\nconst handleSave = async () => {\nawait mutation.mutateAsync(data);\n}"

    assert rule.analyze_regex("src/components/Form.tsx", valid, _facts()) == []
    assert len(rule.analyze_regex("src/components/Form.tsx", invalid, _facts())) == 1
    assert rule.analyze_regex("src/components/Form.tsx", fp_guard, _facts()) == []


def test_form_double_submit_valid_invalid_fp_guard():
    rule = FormDoubleSubmitRule()
    valid = "<button type=\"submit\" disabled={isSubmitting}>Save</button>"
    invalid = "<form><button type=\"submit\">Save</button></form>"
    fp_guard = "const { processing } = useForm({});\n<button type=\"submit\">Save</button>"

    assert rule.analyze_regex("src/components/Form.tsx", valid, _facts()) == []
    assert len(rule.analyze_regex("src/components/Form.tsx", invalid, _facts())) == 1
    assert rule.analyze_regex("src/pages/InertiaForm.tsx", fp_guard, _facts()) == []


def test_focus_lost_on_route_change_valid_invalid_fp_guard():
    rule = FocusLostOnRouteChangeRule()
    valid = "router.on('finish', () => document.querySelector('main')?.focus());"
    invalid = "router.on('finish', () => announcePageChange());"
    fp_guard = "<Link href=\"/users\">Users</Link>"

    assert rule.analyze_regex("src/layouts/AppLayout.tsx", valid, _facts()) == []
    assert len(rule.analyze_regex("src/layouts/AppLayout.tsx", invalid, _facts())) == 1
    assert rule.analyze_regex("src/layouts/AppLayout.tsx", fp_guard, _facts()) == []


def test_table_missing_headers_valid_invalid_fp_guard():
    rule = TableMissingHeadersRule()
    valid = "<table><tr><th scope=\"col\">Name</th></tr><tr><td>A</td></tr></table>"
    invalid = "<table><tr><td>Name</td><td>Email</td></tr><tr><td>A</td><td>a@test.com</td></tr></table>"
    fp_guard = "<table><tbody><tr><td>1</td><td>2</td></tr></tbody></table>"

    assert rule.analyze_regex("src/components/Table.tsx", valid, _facts()) == []
    assert len(rule.analyze_regex("src/components/Table.tsx", invalid, _facts())) == 1
    assert rule.analyze_regex("src/components/Grid.tsx", fp_guard, _facts()) == []


def test_missing_fieldset_legend_valid_invalid_fp_guard():
    rule = MissingFieldsetLegendRule()
    valid = "<fieldset><legend>Size</legend><input type=\"radio\" name=\"size\" /></fieldset>"
    invalid = "<div><input type=\"radio\" name=\"size\"/><input type=\"radio\" name=\"size\"/></div>"
    fp_guard = "<label><input type=\"checkbox\" /> Accept</label>"

    assert rule.analyze_regex("src/components/Options.tsx", valid, _facts()) == []
    assert len(rule.analyze_regex("src/components/Options.tsx", invalid, _facts())) == 1
    assert rule.analyze_regex("src/components/Terms.tsx", fp_guard, _facts()) == []


def test_video_missing_captions_valid_invalid_fp_guard():
    rule = VideoMissingCaptionsRule()
    valid = "<video src={url} controls><track kind=\"captions\" src=\"/c.vtt\" /></video>"
    invalid = "<video src={url} controls></video>"
    fp_guard = "<video src={url} muted autoPlay></video>"

    assert rule.analyze_regex("src/components/Video.tsx", valid, _facts()) == []
    assert len(rule.analyze_regex("src/components/Video.tsx", invalid, _facts())) == 1
    assert rule.analyze_regex("src/components/HeroVideo.tsx", fp_guard, _facts()) == []


def test_animation_no_pause_control_valid_invalid_fp_guard():
    rule = AnimationNoPauseControlRule()
    valid = "<Spinner className=\"motion-safe:animate-spin\" />"
    invalid = "<Spinner className=\"animate-spin\" />"
    fp_guard = "<div className=\"animate-fade-in duration-150\" />"

    assert rule.analyze_regex("src/components/Spinner.tsx", valid, _facts()) == []
    assert len(rule.analyze_regex("src/components/Spinner.tsx", invalid, _facts())) == 1
    assert rule.analyze_regex("src/components/Fade.tsx", fp_guard, _facts()) == []
