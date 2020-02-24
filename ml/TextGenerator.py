from util_functions import warning

# text generation module
try:
    from textgenrnn import textgenrnn
except ImportError:
    warning('Text generation relies on textgenrnn module, which cant be found.')
    warning('Use "pip3 install textgenrnn"')
    exit()


class TextGenerator:
    def __init__(self, main):
        self.main = main
        self.trained_on = ''
        self.textgen = textgenrnn()

    def _train_on_text(self, text_list):
        epochs_to_train = self.main.options['text_gen_epochs']
        self.textgen.train_on_texts(text_list, num_epochs=1)

    def generate(self, text_list):
        temperature = self.main.options['text_generator_temp']
        generated_list = self.textgen.generate(10, temperature, return_as_list=True)
        return generated_list
