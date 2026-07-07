% !Name            EDA
% !Description     Initial exploratory data analysis of parsed SSH auth log events.
% !Language        python

This notebook walks through loading the sample `auth.log`, parsing it with
``src.parser.parse_file``, and producing the per-IP feature matrix. The
values flow into the rule engine and the ML pipeline in
``scripts/run_pipeline.py``.

Open it in JupyterLab:
    jupyter lab notebooks/01_eda.ipynb
