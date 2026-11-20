from scanners.sast.node import SastKotlinNode,SastNodeParams

def test_node_handles_missing_input():
    result=SastKotlinNode().run(None,SastNodeParams(),{})
    assert result.status=="error" and result.outputs["findings"]==[]

def test_node_handles_invalid_path_without_raising():
    result=SastKotlinNode().run(None,SastNodeParams(),{"project_path":"/definitely/not/a/project"})
    assert result.status=="error"
