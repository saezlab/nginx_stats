#!/usr/bin/Rscript

#
# Visualize statistics processed from nginx logfiles
#
# (c) 2016-2021 Dénes Türei, turei.denes@gmail.com
# License: MIT (Expat) License
#

library(ggplot2)

byctry <- read.table('visitors_by_country', sep = '\t', header = FALSE)
colnames(byctry) <- c('ctry', 'num')

byctry$ctry <- factor(byctry$ctry, levels = byctry$ctry)

b <- ggplot(byctry, aes(x = ctry, y = num)) +
   geom_bar(stat = 'identity', fill = 'black') +
   geom_text(aes(label=num), vjust = -0.5, size = 2, family = 'DINPro') +
   xlab('Country') +
   ylab('Visitors') +
   theme_linedraw() +
   theme(
       text = element_text(family = 'DINPro'),
       axis.text.x = element_text(angle = 90, vjust = 0.5, hjust = 1),
       panel.grid.major.x = element_blank()
    )

ggsave('visitors_by_country.pdf', device = cairo_pdf, width = 12, height = 6)
