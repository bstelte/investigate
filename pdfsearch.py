import PyPDF2, os

searchs = [line.strip() for line in open("input.txt", 'r')]

# Get all the PDF filenames.
pdfFiles = []
for filename in os.listdir('.'):
	if filename.endswith('.pdf'):
		pdfFiles.append(filename)

for filename in pdfFiles:
	pdfFileObj = open(filename, 'rb')
	pdfReader = PyPDF2.PdfFileReader(pdfFileObj)
	for pageNum in range(1, pdfReader.numPages):
		pageObj = pdfReader.getPage(pageNum)
		text = pageObj.extractText()
		text = text.replace("[.]",".")
		for search in searchs:
			if isinstance(search, basestring):
				if (text.find(search) > 0):
					print search+" : "+filename

