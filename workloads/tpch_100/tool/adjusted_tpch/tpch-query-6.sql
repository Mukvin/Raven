-- [origin]

-- same as default

-- [default]

select
	sum(l_extendedprice * l_discount) as revenue
from
	lineitem
where
	cast(l_shipdate as Date) >= date '1993-01-01'
	and cast(l_shipdate as Date) < date '1993-01-01' + interval '1' year
	and l_discount between 0.07 - 0.01 and 0.07 + 0.01
	and l_quantity < 25 
  
