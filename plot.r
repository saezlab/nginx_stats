#!/usr/bin/Rscript

library(ggplot2)

byctry <- read.table('visitors_by_country', sep = '\t', header = FALSE)
colnames(byctry) <- c('ctry', 'num')

byctry$ctry <- factor(byctry$ctry, levels = byctry$ctry)

b <- ggplot(byctry, aes(x = ctry, y = num)) +
	geom_bar(stat = 'identity') +
	geom_text(aes(label=num), vjust = -0.5, size = 2) +
	xlab('Country') +
	ylab('Visitors') +
	theme(axis.text.x = element_text(angle = 90, vjust = 0.5, hjust = 1))

ggsave('visitors_by_country.pdf', device = cairo_pdf, width = 12, height = 6)
