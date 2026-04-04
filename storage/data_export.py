import pandas as pd

class DataExporter:

    def __init__(self, packets):

        self.packets = packets

    def export_csv(self, path):

        df = pd.DataFrame(self.packets)

        df.to_csv(path, index=False)

    def export_excel(self, path):

        df = pd.DataFrame(self.packets)

        df.to_excel(path, index=False)