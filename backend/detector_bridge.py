from pathlib import Path

from detector.argus_detector import ArgusFusionModel, ArgusOneDetector, train_model


MODEL_PATH = (
    Path(__file__).resolve().parents[1]
    / "argus_one_hybrid_model.json"
)


def load_model():
    if MODEL_PATH.exists():
        return ArgusFusionModel.load(MODEL_PATH)

    model = train_model()
    model.save(MODEL_PATH)
    return model


model = load_model()


# Create the streaming detector using the trained model
detector = ArgusOneDetector(model)


def detect_flow(flow):
    """
    Send an incoming network flow to ARGUS-ONE.
    """

    flow_data = flow.model_dump()

    result = detector.process_flow(flow_data)

    return result
